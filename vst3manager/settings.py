# -*- coding: utf-8 -*-
"""Настройки VST3 Manager: %APPDATA%\\VST3Manager\\settings.json.

Пока хранит только кастомные папки сканирования; при расширении — писать сюда.
"""
import json
import os
from pathlib import Path

SETTINGS_PATH = Path(os.environ.get("APPDATA", str(Path.home()))) / "VST3Manager" / "settings.json"


def load_settings():
    try:
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(data):
    try:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    except Exception:
        pass


def custom_roots():
    roots = load_settings().get("custom_roots", [])
    return [p for p in roots if p] if isinstance(roots, list) else []
