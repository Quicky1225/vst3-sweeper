# -*- coding: utf-8 -*-
"""Безопасное удаление: ZIP-бэкап -> корзина -> журнал. Восстановление из бэкапа."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

try:
    from send2trash import send2trash
except ImportError:
    send2trash = None

APP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "VST3Manager"
BACKUP_DIR = APP_DIR / "backups"
JOURNAL_PATH = APP_DIR / "journal.json"


def ensure_dirs():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _sanitize(name):
    return re.sub(r'[<>:"/\\|?*]+', "_", name).strip() or "plugin"


def load_journal():
    try:
        return json.loads(JOURNAL_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"operations": []}


def save_journal(j):
    ensure_dirs()
    JOURNAL_PATH.write_text(json.dumps(j, ensure_ascii=False, indent=2),
                            encoding="utf-8")


def add_operation(op):
    j = load_journal()
    j.setdefault("operations", []).insert(0, op)
    save_journal(j)


def mark_restored(op_id):
    j = load_journal()
    for op in j.get("operations", []):
        if op.get("id") == op_id:
            op["status"] = "restored"
    save_journal(j)


# ----------------------------- реестр -----------------------------

def _split_key(full_key):
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE,
             "HKCR": winreg.HKEY_CLASSES_ROOT, "HKU": winreg.HKEY_USERS}
    hive_name, _, rest = full_key.partition("\\")
    return hives.get(hive_name.upper()), rest


def export_registry(full_key, dest_file):
    """reg export в .reg для бэкапа. True при успехе."""
    try:
        r = subprocess.run(["reg", "export", full_key, str(dest_file), "/y"],
                           capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def delete_registry_tree(full_key):
    """Рекурсивное удаление ключа реестра. True при успехе."""
    import winreg
    hive, rest = _split_key(full_key)
    if hive is None or not rest:
        return False

    def rec(h, path):
        try:
            with winreg.OpenKey(h, path, 0, winreg.KEY_READ) as k:
                subs, i = [], 0
                while True:
                    try:
                        subs.append(winreg.EnumKey(k, i))
                    except OSError:
                        break
                    i += 1
            for s in subs:
                rec(h, f"{path}\\{s}")
            winreg.DeleteKey(h, path)
            return True
        except OSError:
            return False

    return rec(hive, rest)


# --------------------------- удаление -----------------------------

def _filter_ini(file_path, substrings):
    """Удаляет секции INI-файла, содержащие любой из substrings.
    Возвращает число удалённых секций. Файл перезаписывается."""
    p = Path(file_path)
    raw = p.read_bytes()
    try:
        text = raw.decode("utf-8")
        enc = "utf-8"
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
        enc = "latin-1"
    lines = text.splitlines()
    lows = [s.lower() for s in substrings if s]
    out, dropped, i = [], 0, 0
    while i < len(lines):
        if lines[i].lstrip().startswith("["):
            j = i + 1
            while j < len(lines) and not lines[j].lstrip().startswith("["):
                j += 1
            block = lines[i:j]
            if any(s in "\n".join(block).lower() for s in lows):
                dropped += 1
            else:
                out.extend(block)
            i = j
        else:
            out.append(lines[i])
            i += 1
    if dropped:
        p.write_bytes(("\r\n".join(out) + "\r\n").encode(enc))
    return dropped


def backup_and_delete(entries, paths, registry_keys, ini_files=None, progress=None):
    """Бэкап (zip + экспорт реестра + копии ini) и удаление в корзину.

    entries       — список плагинов из отчёта сканера (их бандлы удаляются всегда)
    paths         — связанные папки/файлы (пресеты, данные вендора, побочные DLL, кэши DAW)
    registry_keys — ключи реестра («HKCU\\Software\\…»)
    ini_files     — ini-кэши DAW: копия попадает в архив, затем записи плагина чистятся
    """
    ini_files = [f for f in (ini_files or []) if Path(f).is_file()]
    if send2trash is None:
        raise RuntimeError("Не установлен пакет send2trash: pip install send2trash")

    ensure_dirs()
    op_id = uuid.uuid4().hex[:12]
    ts = time.strftime("%Y%m%d_%H%M%S")
    if len(entries) == 1:
        title = _sanitize(f"{entries[0].get('vendor') or 'Unknown'} - "
                          f"{entries[0].get('name') or 'plugin'}")
    else:
        vendors = sorted({e.get("vendor") or "Unknown" for e in entries})
        head = vendors[0] if len(vendors) == 1 else vendors[0] + " и др."
        title = _sanitize(f"{head} - {len(entries)} plugins")
    zip_path = BACKUP_DIR / f"{ts}_{op_id}_{title}.zip"

    items = []
    for i, e in enumerate(entries):
        src = Path(e["path"])
        items.append({"type": "dir" if src.is_dir() else "file",
                      "path": str(src), "arc": f"bundle_{i}"})
    seen = {it["path"].lower() for it in items}
    for i, p in enumerate(paths):
        pp = Path(p)
        if str(pp).lower() not in seen:
            items.append({"type": "dir" if pp.is_dir() else "file",
                          "path": str(pp), "arc": f"extra_{i}"})

    def report(msg):
        if progress:
            try:
                progress(msg)
            except Exception:
                pass

    deleted_ok, reg_deleted, errors, reg_exported = [], [], [], []

    report(f"Бэкап: {zip_path.name}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = {"id": op_id, "timestamp": ts, "entries": entries,
                    "registry_keys": list(registry_keys), "items": items,
                    "modified_files": [{"path": f,
                                        "arc": f"daw_ini_{i}_{Path(f).name}"}
                                       for i, f in enumerate(ini_files)]}
        z.writestr("manifest.json",
                   json.dumps(manifest, ensure_ascii=False, indent=2))
        for it in items:
            src = Path(it["path"])
            if not src.exists():
                continue
            if it["type"] == "dir":
                base = src.parent
                for dp, _dn, fn in os.walk(src):
                    for f in fn:
                        fp = Path(dp) / f
                        z.write(fp, f"{it['arc']}/{fp.relative_to(base)}")
                report(f"Бэкап: {src.name}")
            else:
                z.write(src, f"{it['arc']}/{src.name}")
        for i, key in enumerate(registry_keys):
            tmp = Path(tempfile.gettempdir()) / f"vst3m_{op_id}_{i}.reg"
            if export_registry(key, tmp):
                z.write(tmp, f"reg_{i}.reg")
                reg_exported.append(key)
                report(f"Бэкап реестра: {key}")
            else:
                errors.append(f"реестр: не удалось экспортировать {key} — ключ не удалён")
            tmp.unlink(missing_ok=True)
        for i, ini in enumerate(ini_files):
            z.write(ini, f"daw_ini_{i}_{Path(ini).name}")
            report(f"Бэкап кэша DAW: {Path(ini).name}")

    for it in items:
        src = Path(it["path"])
        if not src.exists():
            continue
        report(f"Удаление в корзину: {src.name}")
        try:
            send2trash(str(src))
            deleted_ok.append(str(src))
        except Exception as e:
            errors.append(f"{src}: {e}")

    for key in reg_exported:  # удаляем только то, что успели забэкапить
        if delete_registry_tree(key):
            reg_deleted.append(key)
        else:
            errors.append(f"реестр: не удалось удалить {key} (нужны права администратора?)")

    for ini in ini_files:
        report(f"Чистка кэша DAW: {Path(ini).name}")
        try:
            _filter_ini(ini, [e["path"] for e in entries])
        except Exception as e:
            errors.append(f"кэш DAW {ini}: {e}")

    status = "deleted" if not errors and deleted_ok else \
             ("partial" if deleted_ok or reg_deleted else "failed")
    op = {"id": op_id, "timestamp": ts,
          "plugin": f"{entries[0].get('vendor') or ''} — {entries[0].get('name')}".strip(" —")
                    if len(entries) == 1 else f"{len(entries)} плагинов",
          "vendor": entries[0].get("vendor"),
          "backup_zip": str(zip_path),
          "deleted_paths": deleted_ok,
          "registry_deleted": reg_deleted,
          "errors": errors,
          "status": status}
    add_operation(op)
    return op


# -------------------------- восстановление -------------------------

def restore_operation(op):
    """Восстановление всего удалённого из ZIP-бэкапа операции."""
    zip_path = Path(op.get("backup_zip", ""))
    if not zip_path.exists():
        return False, [f"Бэкап не найден: {zip_path}"]
    errors = []
    tmp = None
    try:
        with zipfile.ZipFile(zip_path) as z:
            manifest = json.loads(z.read("manifest.json").decode("utf-8"))
            tmp = Path(tempfile.mkdtemp(prefix="vst3m_restore_"))
            z.extractall(tmp)
            for it in manifest.get("items", []):
                src_root = tmp / it["arc"]
                dst = Path(it["path"])
                if not src_root.exists() or dst.exists():
                    if dst.exists():
                        errors.append(f"{dst}: уже существует, пропущено")
                    continue
                try:
                    if it["type"] == "dir":
                        children = list(src_root.iterdir())
                        content = children[0] if len(children) == 1 and \
                            children[0].is_dir() else src_root
                        shutil.copytree(content, dst)
                    else:
                        files = [c for c in src_root.iterdir() if c.is_file()]
                        if files:
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(files[0], dst)
                except Exception as e:
                    errors.append(f"{dst}: {e}")
            for m in manifest.get("modified_files", []):
                src = tmp / m["arc"]
                if src.exists():
                    try:
                        shutil.copy2(src, m["path"])
                    except Exception as e:
                        errors.append(f"{m['path']}: {e}")
            # реестр: импорт .reg обратно
            for i, key in enumerate(manifest.get("registry_keys", [])):
                reg_file = tmp / f"reg_{i}.reg"
                if reg_file.exists():
                    try:
                        r = subprocess.run(["reg", "import", str(reg_file)],
                                           capture_output=True, timeout=30)
                        if r.returncode != 0:
                            errors.append(
                                f"реестр {key}: ошибка импорта (нужны права администратора?)")
                    except Exception as e:
                        errors.append(f"реестр {key}: {e}")
    except Exception as e:
        errors.append(f"бэкап: {e}")
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return not errors, errors
