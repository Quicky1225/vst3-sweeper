# -*- coding: utf-8 -*-
"""E2E-проверка cleaner: бэкап -> корзина -> ini/реестр -> восстановление.
Всё происходит во временной папке, реальные плагины не затрагиваются."""
import json
import os
import shutil
import sys
import tempfile
import winreg
import zipfile
from pathlib import Path

tmp = Path(tempfile.mkdtemp(prefix="vst3m_test_"))
os.environ["APPDATA"] = str(tmp / "appdata")  # журнал, бэкапы и «FL Studio» — в temp
sys.path.insert(0, str(Path(__file__).resolve().parent / "vst3manager"))
import cleaner
import daw

# --- фейковый бандл ---
bundle = tmp / "Common" / "VST3" / "FakeVendor" / "FakePlugin.vst3"
(bundle / "Contents" / "x86_64-win").mkdir(parents=True)
(bundle / "Contents" / "x86_64-win" / "FakePlugin.vst3").write_bytes(b"MZ fake dll")
(bundle / "moduleinfo.json").write_text(
    '{"Name":"FakePlugin","Version":"1.0","FactoryInfos":[{"Vendor":"FakeVendor"}]}',
    encoding="utf-8")
presets = tmp / "docs" / "VST3 Presets" / "FakeVendor"
presets.mkdir(parents=True)
(presets / "default.vstpreset").write_bytes(b"preset")
data = tmp / "vendor_data" / "FakeVendor"
data.mkdir(parents=True)
(data / "settings.ini").write_text("x=1", encoding="utf-8")

# --- фейковые кэши DAW ---
(tmp / "appdata" / "REAPER").mkdir(parents=True)
ini = tmp / "appdata" / "REAPER" / "reaper-vstplugins64.ini"
ini.write_text("[VST: FakePlugin (FakeVendor)]\r\nmain=" + str(bundle) +
               "\r\n\r\n[VST: Keep (Other)]\r\nmain=C:\\keep.vst3\r\n",
               encoding="utf-8")
fl_db = (tmp / "appdata" / "Image-Line" / "FL Studio" / "Presets" /
         "Plugin database" / "Installed" / "Effects")
fl_db.mkdir(parents=True)
fl_file = fl_db / "FakePlugin.fst"
fl_file.write_bytes(b"fst")

# --- тестовый ключ реестра ---
key = r"Software\VST3ManagerTest"
with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
    winreg.SetValueEx(k, "TestValue", 0, winreg.REG_SZ, "hello")


def key_exists():
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, key)
        return True
    except FileNotFoundError:
        return False


entry = {"path": str(bundle), "kind": "dir", "vendor": "FakeVendor",
         "name": "FakePlugin", "size_bytes": 100, "file_count": 2,
         "related": {"presets": [], "vendor_data": [], "registry": []}}

# --- daw.mentions находит кэши ---
mi = daw.mentions([entry])
assert str(fl_file) in mi["fl_items"], mi
assert str(ini) in mi["reaper_inis"], mi
print("daw.mentions OK:", len(mi["fl_items"]), "FL-файлов,", len(mi["reaper_inis"]), "ini")

# --- удаление с бэкапом ---
op = cleaner.backup_and_delete([entry], [str(presets), str(data), str(fl_file)],
                               [f"HKCU\\{key}"], ini_files=[str(ini)],
                               progress=print)
print("status:", op["status"], "| errors:", op["errors"])
assert op["status"] == "deleted", op
assert not bundle.exists(), "бандл не удалён"
assert not presets.exists() and not data.exists() and not fl_file.exists()
assert not key_exists(), "ключ реестра не удалён"

txt = ini.read_text(encoding="utf-8")
assert "FakePlugin (FakeVendor)" not in txt, "секция REAPER не удалена"
assert "[VST: Keep (Other)]" in txt, "чужая секция пострадала"

with zipfile.ZipFile(op["backup_zip"]) as z:
    m = json.loads(z.read("manifest.json"))
    names = z.namelist()
print(f"zip ok: {len(m['items'])} объектов, ключей: {len(m['registry_keys'])}, "
      f"ini в архиве: {len(m['modified_files'])}, файлов в архиве: {len(names)}")
assert len(m["items"]) == 4 and len(m["registry_keys"]) == 1
assert len(m["modified_files"]) == 1
assert any(n.startswith("daw_ini_") for n in names)

# --- восстановление ---
ok, errs = cleaner.restore_operation(op)
print("restore:", ok, errs)
assert ok, errs
assert bundle.exists() and (bundle / "moduleinfo.json").exists()
assert (presets / "default.vstpreset").exists() and (data / "settings.ini").exists()
assert fl_file.exists(), "FL-запись не восстановлена"
assert key_exists(), "ключ реестра не восстановлен"
txt2 = ini.read_text(encoding="utf-8")
assert "FakePlugin (FakeVendor)" in txt2, "ini не восстановлен из бэкапа"
with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
    v, _ = winreg.QueryValueEx(k, "TestValue")
assert v == "hello", v

# --- режим без бэкапа + навсегда ---
bundle2 = tmp / "Common" / "VST3" / "OnceOnly.vst3"
(bundle2 / "Contents").mkdir(parents=True)
(bundle2 / "Contents" / "x.vst3").write_bytes(b"MZ")
entry2 = {"path": str(bundle2), "kind": "dir", "vendor": "OnceOnly",
          "name": "OnceOnly", "size_bytes": 1, "file_count": 1,
          "related": {"presets": [], "vendor_data": [], "registry": []}}
op2 = cleaner.backup_and_delete([entry2], [], [], progress=print,
                                backup=False, permanent=True)
assert op2["status"] == "deleted", op2
assert op2["backup_zip"] is None and op2["no_backup"] and op2["permanent"]
assert not bundle2.exists(), "папка не удалена навсегда"
print("no-backup + permanent OK")

# --- уборка ---
winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
shutil.rmtree(tmp, ignore_errors=True)
print("E2E OK: бэкап, корзина, реестр, ini DAW и восстановление работают")
