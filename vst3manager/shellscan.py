# -*- coding: utf-8 -*-
"""Перечисление плагинов внутри «оболочек» (WaveShell и т.п.) через VST3-фабрику.

Оболочка — один .vst3, внутри которого десятки самостоятельных плагинов
(Waves, Slate и т.д.). Читаем IPluginFactory через ctypes: getFactoryInfo,
countClasses, getClassInfo2. DLL загружается в ИЗОЛИРОВАННОМ подпроцессе
(main.py --dump-classes), чтобы крэш/зависание оболочки не уронил менеджер.
"""
import ctypes
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

kResultOk = 0
AUDIO_CATEGORY = "Audio Module Class"


class PFactoryInfo(ctypes.Structure):
    _fields_ = [("vendor", ctypes.c_char * 64),
                ("url", ctypes.c_char * 40),
                ("email", ctypes.c_char * 32),
                ("flags", ctypes.c_int32)]


class PClassInfo(ctypes.Structure):
    """Базовая IPluginFactory (без getClassInfo2 — у WaveShell слот 6 это createInstance)."""
    _fields_ = [("cid", ctypes.c_uint8 * 16),
                ("cardinality", ctypes.c_int32),
                ("category", ctypes.c_char * 32),
                ("name", ctypes.c_char * 64)]


def enumerate_classes_incremental(dll_path, out_file, start=0, flush_every=1):
    """То же, но результат дописывается в out_file по ходу: если DLL упадёт
    на середине перечисления, всё прочитанное до падения сохранится."""
    out = {}
    p = Path(dll_path)
    if not p.is_file():
        out = {"error": f"нет файла: {p}"}
        _atomic_write(out_file, out)
        return out
    try:
        os.add_dll_directory(str(p.parent))
        k32 = ctypes.windll.kernel32
        k32.LoadLibraryExW.restype = ctypes.c_void_p
        k32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p,
                                       ctypes.c_uint32]
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        k32.GetProcAddress.restype = ctypes.c_void_p
        h = k32.LoadLibraryExW(str(p), None, 0x8)  # LOAD_WITH_ALTERED_SEARCH_PATH
        if not h:
            out = {"error": "LoadLibraryExW не смог загрузить DLL"}
            _atomic_write(out_file, out)
            return out

        def export(name):
            return k32.GetProcAddress(h, name) or None

        init_addr = export(b"InitDll")
        if init_addr:
            try:
                ctypes.CFUNCTYPE(ctypes.c_bool)(init_addr)()
            except Exception:
                pass
        gp_addr = export(b"GetPluginFactory")
        if not gp_addr:
            out = {"error": "нет экспорта GetPluginFactory"}
            _atomic_write(out_file, out)
            return out
        factory = ctypes.CFUNCTYPE(ctypes.c_void_p)(gp_addr)()
        if not factory:
            out = {"error": "GetPluginFactory вернул null"}
            _atomic_write(out_file, out)
            return out
        # vtable: [0..2] IUnknown, [3] getFactoryInfo, [4] countClasses,
        #         [5] getClassInfo (есть у всех фабрик)
        vtbl_addr = ctypes.c_void_p.from_address(factory).value
        if not vtbl_addr:
            out = {"error": "пустой vtable"}
            _atomic_write(out_file, out)
            return out
        slot = ctypes.sizeof(ctypes.c_void_p)

        def vfn(idx):
            return ctypes.c_void_p.from_address(vtbl_addr + idx * slot).value

        proto_gfi = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p,
                                     ctypes.POINTER(PFactoryInfo))
        proto_cnt = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p)
        proto_gci = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p,
                                     ctypes.c_int32, ctypes.POINTER(PClassInfo))
        get_factory_info = proto_gfi(vfn(3))
        count_classes = proto_cnt(vfn(4))
        get_class_info = proto_gci(vfn(5))
        finfo = PFactoryInfo()
        get_factory_info(factory, ctypes.byref(finfo))
        out = {"factory": finfo.vendor.decode(errors="replace").strip(),
               "classes": []}
        _atomic_write(out_file, out)
        total = count_classes(factory)
        out = {"factory": finfo.vendor.decode(errors="replace").strip(),
               "classes": [], "total": total, "last_index": start - 1}
        _atomic_write(out_file, out)
        for i in range(start, total):
            last_saved = False
            try:
                ci = PClassInfo()
                if get_class_info(factory, i, ctypes.byref(ci)) == kResultOk:
                    cat = ci.category.decode(errors="replace").strip()
                    if cat == AUDIO_CATEGORY:
                        out["classes"].append({
                            "name": ci.name.decode(errors="replace").strip(),
                            "vendor": finfo.vendor.decode(errors="replace").strip(),
                            "version": "",
                        })
            except Exception:
                # DLL упала на этом классе — пропускаем его на перезапуске
                out["last_index"] = i
                _atomic_write(out_file, out)
                break
            out["last_index"] = i
            _atomic_write(out_file, out)
        _atomic_write(out_file, out)
        return out
    except Exception as e:
        out = {"error": str(e), **out}
        _atomic_write(out_file, out)
        return out


def _atomic_write(out_file, data):
    tmp = Path(str(out_file) + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, out_file)


def enumerate_classes(dll_path):
    """Загрузить DLL и вернуть {"factory": ..., "classes": [...]} или {"error": ...}.

    Вызывается в подпроцессе — здесь можно упасть безопасно."""
    try:
        p = Path(dll_path)
        if not p.is_file():
            return {"error": f"нет файла: {p}"}
        os.add_dll_directory(str(p.parent))
        # LOAD_WITH_ALTERED_SEARCH_PATH: зависимости DLL ищутся в её папке —
        # без этого WaveShell и им подобные падают при загрузке
        k32 = ctypes.windll.kernel32
        k32.LoadLibraryExW.restype = ctypes.c_void_p
        k32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p,
                                       ctypes.c_uint32]
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        k32.GetProcAddress.restype = ctypes.c_void_p
        h = k32.LoadLibraryExW(str(p), None, 0x8)  # LOAD_WITH_ALTERED_SEARCH_PATH
        if not h:
            return {"error": "LoadLibraryExW не смог загрузить DLL"}

        def export(name):
            return k32.GetProcAddress(h, name) or None

        init_addr = export(b"InitDll")
        if init_addr:
            try:
                ctypes.CFUNCTYPE(ctypes.c_bool)(init_addr)()
            except Exception:
                pass
        gp_addr = export(b"GetPluginFactory")
        if not gp_addr:
            return {"error": "нет экспорта GetPluginFactory"}
        factory = ctypes.CFUNCTYPE(ctypes.c_void_p)(gp_addr)()
        if not factory:
            return {"error": "GetPluginFactory вернул null"}
        # vtable: [0..2] IUnknown, [3] getFactoryInfo, [4] countClasses,
        #         [5] getClassInfo, [6] getClassInfo2, [7] createInstance
        # читаем по адресам явно: cast от инстанса даёт адрес переменной, не значение
        vtbl_addr = ctypes.c_void_p.from_address(factory).value
        if not vtbl_addr:
            return {"error": "пустой vtable"}
        slot = ctypes.sizeof(ctypes.c_void_p)

        def vfn(idx):
            return ctypes.c_void_p.from_address(vtbl_addr + idx * slot).value

        proto_gfi = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p,
                                     ctypes.POINTER(PFactoryInfo))
        proto_cnt = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p)
        proto_gci = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p,
                                     ctypes.c_int32, ctypes.POINTER(PClassInfo))
        get_factory_info = proto_gfi(vfn(3))
        count_classes = proto_cnt(vfn(4))
        get_class_info = proto_gci(vfn(5))  # getClassInfo есть у всех фабрик
        finfo = PFactoryInfo()
        get_factory_info(factory, ctypes.byref(finfo))
        out = {"factory": finfo.vendor.decode(errors="replace").strip(),
               "classes": []}
        for i in range(count_classes(factory)):
            ci = PClassInfo()
            if get_class_info(factory, i, ctypes.byref(ci)) == kResultOk:
                cat = ci.category.decode(errors="replace").strip()
                if cat == AUDIO_CATEGORY:
                    out["classes"].append({
                        "name": ci.name.decode(errors="replace").strip(),
                        "vendor": finfo.vendor.decode(errors="replace").strip(),
                        "version": "",
                    })
        return out
    except Exception as e:
        return {"error": str(e)}


def subprocess_command(dll_path, out_file, start=0):
    """Изолированный запуск: свой процесс -> JSON в out_file.

    Через файл, а не stdout: у --windowed exe stdout отсутствует."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--dump-classes", str(dll_path), str(out_file),
                str(start)]
    main_py = Path(__file__).with_name("main.py").resolve()
    return [sys.executable, str(main_py), "--dump-classes", str(dll_path),
            str(out_file), str(start)]


def scan_shell(dll_path, timeout=40, max_attempts=8):
    """Перечислить классы оболочки в подпроцессе; [] при любой ошибке.

    DLL может жёстко падать на отдельных классах: запускаем несколько раз,
    продолжая с сохранённого last_index и принудительно пропуская падучие."""
    if not dll_path:
        return []
    merged, seen, factory_name, total = [], set(), "", 0
    start = 0
    for _attempt in range(max_attempts):
        fd, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            subprocess.run(subprocess_command(dll_path, out_path, start),
                           timeout=timeout, capture_output=True)
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
        except Exception:
            data = {}
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
        factory_name = data.get("factory") or factory_name
        total = data.get("total") or total
        for c in data.get("classes", []):
            n = c.get("name")
            if n and n not in seen:
                seen.add(n)
                merged.append(c)
        last = data.get("last_index", start - 1)
        if total and last >= total - 1:
            break  # перечислили всё
        nxt = max(last + 1, start + 1)  # гарантия прогресса даже при затыке
        start = nxt
    return merged


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(json.dumps(enumerate_classes(sys.argv[1])))
