# -*- coding: utf-8 -*-
"""VST3 Manager — точка входа.

Запуск GUI:        python vst3manager/main.py
Самопроверка:      python vst3manager/main.py --selftest
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def selftest():
    """Запуск без окна: скан + построение интерфейса офскрин, проверка связки."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import scanner
    rep = scanner.scan()
    assert rep["plugin_count"] > 0, "сканер не нашёл ни одного плагина"

    from PySide6.QtWidgets import QApplication
    import theme
    import ui
    app = QApplication([])
    app.setStyleSheet(theme.APP_QSS)
    w = ui.MainWindow(scan_on_start=False)
    w.apply_report(rep)
    assert w.tree.topLevelItemCount() > 0, "дерево пустое"
    vendor_item = w.tree.topLevelItem(0)
    w.tree.setCurrentItem(vendor_item)
    assert w.details.toPlainText(), "карточка вендора пустая"
    if vendor_item.childCount():
        w.tree.setCurrentItem(vendor_item.child(0))
        assert "Путь" in w.details.toPlainText(), "карточка плагина не построилась"
    print(f"SELFTEST OK: {rep['plugin_count']} плагинов, "
          f"{w.tree.topLevelItemCount()} вендоров")
    # жёсткий выход: teardown Qt при мгновенном завершении даёт сегфолт
    os._exit(0)


def screenshot():
    """Режим --shot: показать окно с готовым отчётом, сохранить preview.png и выйти."""
    import json
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    import theme
    import ui
    app = QApplication(sys.argv)
    app.setStyleSheet(theme.APP_QSS)
    w = ui.MainWindow(scan_on_start=False)
    rep_path = Path(__file__).resolve().parent.parent / "vst3_report.json"
    if rep_path.exists():
        rep = json.loads(rep_path.read_text(encoding="utf-8"))
        w.apply_report(rep)
    # для превью: выбрать плагин с побочными DLL (показать «хвосты»)
    from PySide6.QtCore import Qt
    picked = None
    for i in range(w.tree.topLevelItemCount()):
        v = w.tree.topLevelItem(i)
        if v.text(0) == "(без вендора)":
            continue
        for j in range(v.childCount()):
            d = v.child(j).data(0, Qt.UserRole)
            if d and d["entry"].get("sidecar_dlls"):
                picked = v.child(j)
                break
        if picked:
            break
    if picked is None:
        for i in range(w.tree.topLevelItemCount()):
            v = w.tree.topLevelItem(i)
            if v.childCount() and v.text(0) != "(без вендора)":
                picked = v.child(0)
                break
    if picked is not None:
        w.tree.setCurrentItem(picked)
    w.resize(1150, 720)
    w.show()

    def grab():
        w.grab().save(str(Path(__file__).with_name("preview.png")))
        os._exit(0)  # teardown Qt даёт сегфолт — выходим жёстко после сохранения

    QTimer.singleShot(1500, grab)
    return app.exec()


def main():
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("Не установлен PySide6. Установи зависимости:")
        print("  python -m pip install PySide6 send2trash pefile")
        return 1
    import theme
    import ui
    app = QApplication(sys.argv)
    app.setApplicationName("VST3 Manager")
    app.setStyleSheet(theme.APP_QSS)
    w = ui.MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    if "--shot" in sys.argv:
        sys.exit(screenshot() or 0)
    sys.exit(main() or 0)
