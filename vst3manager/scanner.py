# -*- coding: utf-8 -*-
"""Сканер VST3: находит плагины и связанные с ними файлы. Только чтение."""
import ctypes
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

HOME = Path.home()
APPDATA = os.environ.get("APPDATA", "")
LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
PROGRAMDATA = os.environ.get("ProgramData", "")
PROGRAMFILES = os.environ.get("ProgramFiles", r"C:\Program Files")
PROGRAMFILES_X86 = os.environ.get("ProgramFiles(x86)", "")

try:
    import pefile  # опционально: читает CompanyName из ресурсов PE
except ImportError:
    pefile = None


def norm(s):
    """Нормализация имени вендора/плагина для сопоставления."""
    return re.sub(r"[^a-z0-9а-яё]", "", (s or "").lower())


def vst3_roots():
    """Все папки, где Windows/DAW ищут VST3: стандартные + из реестра."""
    roots = [
        Path(PROGRAMFILES) / "Common Files" / "VST3",
        Path(LOCALAPPDATA) / "Programs" / "Common" / "VST3" if LOCALAPPDATA else None,
        Path(PROGRAMFILES_X86) / "Common Files" / "VST3" if PROGRAMFILES_X86 else None,
    ]
    try:
        import winreg
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, r"SOFTWARE\VST") as k:
                    val, _ = winreg.QueryValueEx(k, "VST3Path")
                    for p in (val if isinstance(val, (list, tuple)) else [val]):
                        if p:
                            roots.append(Path(p))
            except OSError:
                pass
    except ImportError:
        pass

    out, seen = [], set()
    for r in roots:
        if r is None:
            continue
        try:
            rp = r.resolve()
        except OSError:
            continue
        if rp.is_dir() and str(rp).lower() not in seen:
            seen.add(str(rp).lower())
            out.append(rp)
    return out


def find_bundles(root):
    """Все бандлы .vst3 (папки и одиночные файлы) в дереве корня."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        for name in dirnames:
            if name.lower().endswith(".vst3"):
                found.append({"path": d / name, "kind": "dir",
                              "vendor_hint": d.name if d != root else None})
        for name in filenames:
            if name.lower().endswith(".vst3"):
                found.append({"path": d / name, "kind": "file",
                              "vendor_hint": d.name if d != root else None})
        # внутрь бандла не спускаемся — там бинарник, а не другие плагины
        dirnames[:] = [x for x in dirnames if not x.lower().endswith(".vst3")]
    return found


def read_moduleinfo(bdir):
    """moduleinfo.json из бандла (имя/версия/вендор от производителя)."""
    cands = [bdir / "moduleinfo.json",
             bdir / "Contents" / "moduleinfo.json",
             bdir / "Contents" / "Resources" / "moduleinfo.json"]
    for c in cands:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
    try:
        for hit in bdir.rglob("moduleinfo.json"):
            try:
                return json.loads(hit.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
    except OSError:
        pass
    return None


def parse_moduleinfo(mi):
    name = version = vendor = None
    if isinstance(mi, dict):
        name, version = mi.get("Name"), mi.get("Version")
        fi = mi.get("FactoryInfos")
        if isinstance(fi, list) and fi and isinstance(fi[0], dict):
            vendor = fi[0].get("Vendor")
        elif isinstance(fi, dict):
            vendor = fi.get("Vendor")
        if not vendor:
            fi2 = mi.get("Factory Info")
            if isinstance(fi2, dict):
                vendor = fi2.get("Vendor")
    return name, version, vendor


def pe_strings(dll_path):
    """CompanyName/ProductName/FileDescription из ресурсов PE-файла."""
    if pefile is None:
        return {}
    try:
        pe = pefile.PE(str(dll_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        out = {}
        for fileinfo_list in getattr(pe, "FileInfo", None) or []:
            for fi in fileinfo_list:
                for st in getattr(fi, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        k = k.decode(errors="replace") if isinstance(k, bytes) else k
                        v = v.decode(errors="replace") if isinstance(v, bytes) else v
                        out.setdefault(k, v)
        pe.close()
        return out
    except Exception:
        return {}


def pe_imports(dll_path):
    """Список импортируемых DLL из таблицы импортов PE-файла."""
    if pefile is None:
        return []
    try:
        pe = pefile.PE(str(dll_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        out = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
            dll = entry.dll
            if isinstance(dll, bytes):
                dll = dll.decode(errors="replace")
            if dll:
                out.append(dll)
        pe.close()
        return out
    except Exception:
        return []


_SKIP_DLL_PREFIX = ("api-ms-", "ext-ms-", "nt-ms-")
_DLL_STRING = re.compile(r"[A-Za-z0-9_\- .]{2,60}\.dll", re.IGNORECASE)


def _string_dll_candidates(dll_path, max_read=16 << 20):
    """Имена *.dll из строк бинарника — ловит зависимости, подгружаемые
    через LoadLibrary (их нет в статической таблице импортов)."""
    try:
        with open(dll_path, "rb") as f:
            data = f.read(max_read)
        return {m.group(0) for m in _DLL_STRING.finditer(data.decode("latin-1"))}
    except Exception:
        return set()


def find_sidecar_dlls(entry, limit=50):
    """DLL-зависимости плагина, лежащие рядом с ним, но ВНЕ бандла.

    Рекурсивно разбираем импорт-таблицы плагина и найденных DLL и смотрим,
    какие из импортируемых файлов реально лежат в папке вендора/корне VST3 —
    именно они останутся сиротами после удаления бандла.
    """
    if pefile is None:
        return []
    bundle = Path(entry["path"])
    bundle_dir = bundle if entry["kind"] == "dir" else bundle.parent
    if entry["kind"] == "dir":
        # DLL лежат в папке вендора рядом с бандлом или в корне VST3
        search_dirs = [bundle_dir.parent, Path(entry["root"])]
    else:
        # одиночный файл-бандл: «россыпь» обычно в той же папке, что и файл
        search_dirs = [bundle_dir, bundle_dir.parent, Path(entry["root"])]
    seen_files, seen_imports, result = set(), set(), []
    queue = [Path(b) for b in entry.get("binaries", []) if Path(b).is_file()]
    steps = 0
    while queue and steps < 60:
        steps += 1
        cur = queue.pop(0)
        key = str(cur).lower()
        if key in seen_files:
            continue
        seen_files.add(key)
        for imp in pe_imports(cur):
            low = imp.lower()
            if low in seen_imports or low.startswith(_SKIP_DLL_PREFIX):
                continue
            seen_imports.add(low)
            for d in search_dirs:
                cand = d / imp
                if cand.is_file():
                    result.append(str(cand))
                    if len(result) >= limit:
                        return _outside(result, bundle, entry["kind"])
                    queue.append(cand)
                    break
    # динамические зависимости: имена *.dll в строках бинарников плагина
    base_names = {Path(r).name.lower() for r in result}
    for b in list(dict.fromkeys(entry.get("binaries", []))):
        for name in _string_dll_candidates(b):
            low = name.lower()
            if low in seen_imports or low.startswith(_SKIP_DLL_PREFIX):
                continue
            for d in search_dirs:
                cand = d / name
                if cand.is_file() and Path(cand).name.lower() not in base_names:
                    result.append(str(cand))
                    base_names.add(Path(cand).name.lower())
                    break
            if len(result) >= limit:
                return _outside(result, bundle, entry["kind"])
    return _outside(result, bundle, entry["kind"])


def _outside(paths, bundle, kind):
    """Убирает пути внутри бандла: для папки-бандла — всё её содержимое,
    для файла-бандла — только сам файл (соседние DLL валидны)."""
    b = str(bundle).lower()
    out = []
    for p in paths:
        lp = str(p).lower()
        if kind == "dir" and (lp == b or lp.startswith(b + os.sep)):
            continue
        if kind == "file" and lp == b:
            continue
        out.append(p)
    return out


def dir_stats(d):
    files = size = 0
    for dp, _dn, fn in os.walk(d):
        for f in fn:
            try:
                size += (Path(dp) / f).stat().st_size
                files += 1
            except OSError:
                pass
    return files, size


def software_key_map():
    """Словарь: нормализованное имя -> ключи HKCU/HKLM\\Software."""
    try:
        import winreg
    except ImportError:
        return {}
    out = {}
    for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                        (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        try:
            with winreg.OpenKey(hive, r"SOFTWARE") as k:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(k, i)
                    except OSError:
                        break
                    i += 1
                    out.setdefault(norm(name), []).append(f"{label}\\Software\\{name}")
        except OSError:
            pass
    return out


def preset_roots():
    roots = [HOME / "Documents" / "VST3 Presets",
             HOME / "OneDrive" / "Documents" / "VST3 Presets",
             HOME / "OneDrive" / "Документы" / "VST3 Presets"]
    return [r for r in roots if r.is_dir()]


def find_related(vendor, presets_dirs, sw_map):
    """Хвосты плагина, найденные по имени вендора (эвристика)."""
    rel = {"presets": [], "vendor_data": [], "registry": []}
    key = norm(vendor)
    if not key:
        return rel
    for pr in presets_dirs:
        try:
            for child in pr.iterdir():
                if child.is_dir() and norm(child.name) == key:
                    rel["presets"].append(str(child))
        except OSError:
            pass
    for base in (APPDATA, LOCALAPPDATA, PROGRAMDATA):
        if not base:
            continue
        try:
            for child in Path(base).iterdir():
                if child.is_dir() and norm(child.name) == key:
                    rel["vendor_data"].append(str(child))
        except OSError:
            pass
    rel["registry"] = sw_map.get(key, [])
    return rel


def find_orphans(plugins, presets_dirs):
    """«Сироты»: папки пресетов вендоров, у которых нет ни одного найденного плагина."""
    known = {norm(e["vendor"]) for e in plugins if e["vendor"]}
    out = []
    for pr in presets_dirs:
        try:
            for child in pr.iterdir():
                if not child.is_dir() or norm(child.name) in known:
                    continue
                files, size = dir_stats(child)
                out.append({"path": str(child), "kind": "dir", "root": str(pr),
                            "vendor": child.name, "name": child.name,
                            "version": None, "binaries": [],
                            "file_count": files, "size_bytes": size,
                            "related": {"presets": [], "vendor_data": [],
                                        "registry": []},
                            "sidecar_dlls": [], "risk": "orphan",
                            "warnings": ["Установленных плагинов этого вендора не найдено"],
                            "orphan": True})
        except OSError:
            pass
    return out


def detect_daw_caches():
    """Кэши/базы плагинов DAW — только обнаружение (чистка на след. этапе)."""
    checks = {
        "FL Studio": Path(APPDATA) / "Image-Line" / "FL Studio" / "Presets" / "Plugin database" if APPDATA else None,
        "REAPER": Path(APPDATA) / "REAPER" / "reaper-vstplugins64.ini" if APPDATA else None,
        "Ableton Live": Path(LOCALAPPDATA) / "Ableton" if LOCALAPPDATA else None,
        "Cubase": Path(APPDATA) / "Steinberg" if APPDATA else None,
        "Studio One": Path(APPDATA) / "PreSonus" if APPDATA else None,
        "Bitwig Studio": Path(APPDATA) / "Bitwig" if APPDATA else None,
        "Waveform (Tracktion)": Path(APPDATA) / "Tracktion" if APPDATA else None,
    }
    return {daw: str(p) for daw, p in checks.items() if p and p.exists()}


def scan(progress_cb=None):
    """Полное сканирование. Возвращает отчёт (dict)."""

    def report(msg):
        if progress_cb:
            try:
                progress_cb(msg)
            except Exception:
                pass

    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    sw_map = software_key_map()
    presets_dirs = preset_roots()
    roots = vst3_roots()
    report("Ищу бандлы .vst3…")

    plugins = []
    for root in roots:
        report(f"Сканирую: {root}")
        for b in find_bundles(root):
            p = b["path"]
            try:
                entry = {"path": str(p), "kind": b["kind"], "root": str(root),
                         "vendor_hint": b["vendor_hint"]}
                if b["kind"] == "dir":
                    mi = read_moduleinfo(p)
                    files, size = dir_stats(p)
                    binaries = [str(x) for x in p.rglob("*.vst3") if x.is_file()]
                else:
                    mi = None
                    files, size = 1, p.stat().st_size
                    binaries = [str(p)]

                name, version, mi_vendor = parse_moduleinfo(mi)
                vendor = mi_vendor or b["vendor_hint"]
                # если moduleinfo нет/неполный — добираем из ресурсов PE
                if (not vendor or not name) and binaries:
                    strings = pe_strings(binaries[0])
                    if not vendor:
                        vendor = strings.get("CompanyName") or b["vendor_hint"]
                    if not name:
                        name = (strings.get("FileDescription")
                                or strings.get("ProductName") or p.stem)
                entry["name"] = name or p.stem
                entry["version"] = version
                entry["vendor"] = vendor
                entry["binaries"] = binaries
                entry["sidecar_dlls"] = find_sidecar_dlls(entry)
                entry["file_count"] = files
                entry["size_bytes"] = size
                entry["related"] = find_related(vendor, presets_dirs, sw_map)
                plugins.append(entry)
            except Exception as exc:  # один кривой бандл не должен ломать скан
                report(f"Пропуск {p.name}: {exc}")

    # сколько плагинов в скане у одного вендора -> пометка «общие данные»
    vendor_counts = {}
    for e in plugins:
        v = norm(e["vendor"])
        if v:
            vendor_counts[v] = vendor_counts.get(v, 0) + 1
    for e in plugins:
        v = norm(e["vendor"])
        rel = e["related"]
        risk, warns = "clean", []
        if any([rel["presets"], rel["vendor_data"], rel["registry"]]):
            risk = "has-related"
        if v and vendor_counts.get(v, 0) > 1 and rel["vendor_data"]:
            risk = "shared-data"
            warns.append(f"Данные вендора общие для {vendor_counts[v]} плагинов в скане")
        e["risk"] = risk
        e["warnings"] = warns

    orphans = find_orphans(plugins, presets_dirs)
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "is_admin": is_admin,
        "roots": [str(r) for r in roots],
        "preset_roots": [str(r) for r in presets_dirs],
        "daw_caches": detect_daw_caches(),
        "plugin_count": len(plugins),
        "total_size_bytes": sum(e["size_bytes"] for e in plugins),
        "orphans": orphans,
        "plugins": sorted(plugins, key=lambda e: (norm(e["vendor"]) or "",
                                                  e["name"].lower())),
    }
