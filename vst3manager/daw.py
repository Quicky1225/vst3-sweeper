# -*- coding: utf-8 -*-
"""Кэши плагинов в DAW: находим упоминания удаляемых плагинов и чистим их.

Поддержка:
  REAPER     — reaper-vstplugins*.ini: секции с путём плагина удаляются.
               Файл заранее копируется в бэкап операции, restore возвращает его.
  FL Studio  — Plugin database: файлы/папки с именем плагина удаляются в корзину.
  Ableton, Cubase и др. — только информирование: пересканируют сами.
"""
import os
from pathlib import Path

import scanner

APPDATA = os.environ.get("APPDATA", "")

REAPER_INIS = ["reaper-vstplugins64.ini", "reaper-vstplugins.ini"]
FL_DB = Path(APPDATA) / "Image-Line" / "FL Studio" / "Presets" / "Plugin database"


def reaper_ini_files():
    base = Path(APPDATA) / "REAPER"
    return [str(base / n) for n in REAPER_INIS if (base / n).is_file()]


def _read_lower(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return ""


def mentions(entries):
    """Что чистить по списку удаляемых плагинов.

    Возвращает {"fl_items": [...], "reaper_inis": [...]}.
    """
    fl_items = []
    names = [scanner.norm(e["name"]) for e in entries if scanner.norm(e["name"])]
    if FL_DB.is_dir() and names:
        for dp, dn, fn in os.walk(FL_DB):
            for x in fn + dn:
                nx = scanner.norm(x)
                if any(n and (n in nx or nx == n) for n in names):
                    fl_items.append(str(Path(dp) / x))
    inis = reaper_ini_files()
    reaper = []
    for e in entries:
        low = str(e["path"]).lower()
        for f in inis:
            if f not in reaper and low in _read_lower(f):
                reaper.append(f)
    return {"fl_items": fl_items, "reaper_inis": reaper}
