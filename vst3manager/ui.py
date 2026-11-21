# -*- coding: utf-8 -*-
"""GUI VST3 Manager (PySide6): дерево плагинов, карточки, удаление с бэкапом."""
import html
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, unquote

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QRadialGradient
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressDialog,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTextBrowser,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

import cleaner
import daw
import scanner
import theme

RISK_LABEL = {"clean": "", "has-related": "есть хвосты",
              "shared-data": "⚠ общие данные", "orphan": "сирота"}


def open_in_explorer(path):
    """Открыть папку в проводнике (или подсветить файл в его папке)."""
    try:
        p = Path(path)
        if p.is_dir():
            os.startfile(str(p))
        elif p.is_file():
            subprocess.Popen(["explorer", "/select,", str(p)])
    except Exception:
        pass


def fmt_size(n):
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} ГБ"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} МБ"
    return f"{n / 1024:.0f} КБ"


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Перезапуск с повышением прав (UAC). Работает и для собранного .exe."""
    import ctypes
    if getattr(sys, "frozen", False):
        target, params = sys.executable, ""
    else:
        target, params = sys.executable, f'"{Path(sys.argv[0]).resolve()}"'
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)
        return True
    except Exception:
        return False


class BloomCanvas(QWidget):
    """Фон в стиле Bloom: тёплая бумага + два неподвижных световых «блума»
    (акцент ~8% верх-справа, «резина» ~5% низ-слева). Блумы никогда не двигаются."""

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(theme.PAPER))
        big = max(self.width(), self.height())
        g1 = QRadialGradient(self.width() * 0.92, self.height() * 0.05, big * 0.55)
        g1.setColorAt(0.0, QColor(175, 69, 41, 22))
        g1.setColorAt(1.0, QColor(175, 69, 41, 0))
        p.fillRect(self.rect(), QBrush(g1))
        g2 = QRadialGradient(self.width() * 0.06, self.height() * 0.95, big * 0.50)
        g2.setColorAt(0.0, QColor(201, 88, 63, 16))
        g2.setColorAt(1.0, QColor(201, 88, 63, 0))
        p.fillRect(self.rect(), QBrush(g2))
        p.end()


class ScanWorker(QThread):
    progress = Signal(str)
    finished_scan = Signal(object)

    def run(self):
        try:
            rep = scanner.scan(progress_cb=self.progress.emit)
        except Exception as e:
            rep = {"error": str(e), "plugin_count": 0, "total_size_bytes": 0,
                   "plugins": [], "roots": [], "daw_caches": {}}
        self.finished_scan.emit(rep)


# ----------------------------- диалог удаления -----------------------------

class DeleteDialog(QDialog):
    """Подтверждение удаления: бандлы всегда, связанные файлы — по чекбоксам."""

    def __init__(self, entries, report, daw_info=None, parent=None):
        super().__init__(parent)
        self.entries = entries
        self.setWindowTitle(f"Удаление: {len(entries)} "
                            f"{'плагин' if len(entries) == 1 else 'плагинов'}")
        self.resize(640, 480)
        v = QVBoxLayout(self)
        total = sum(e["size_bytes"] for e in entries)

        head = QLabel(f"Бандлов к удалению: {len(entries)} ({fmt_size(total)}).\n"
                      f"Бандлы .vst3 удаляются всегда, связанные файлы — по галочкам.")
        head.setWordWrap(True)
        v.addWidget(head)

        # считаем, сколько плагинов вендора ОСТАНЕТСЯ после удаления
        counts, del_counts = {}, {}
        for e in report["plugins"]:
            k = scanner.norm(e["vendor"])
            if k:
                counts[k] = counts.get(k, 0) + 1
        for e in entries:
            k = scanner.norm(e["vendor"])
            del_counts[k] = del_counts.get(k, 0) + 1

        def is_shared(e):
            k = scanner.norm(e["vendor"])
            return (counts.get(k, 0) - del_counts.get(k, 0)) > 0

        def uniq(seq):
            out, seen = [], set()
            for p in seq:
                if p.lower() not in seen:
                    seen.add(p.lower())
                    out.append(p)
            return out

        presets, datas, keys = [], [], []
        owner = {}
        for e in entries:
            rel = e["related"]
            for p in rel["presets"]:
                owner.setdefault(p.lower(), e)
                presets.append(p)
            for p in rel["vendor_data"]:
                owner.setdefault(p.lower(), e)
                datas.append(p)
            for p in rel["registry"]:
                owner.setdefault(p.lower(), e)
                keys.append(p)
        sidecars, owner_sc = [], {}
        for e in entries:
            for p in e.get("sidecar_dlls", []):
                owner_sc.setdefault(p.lower(), e)
                sidecars.append(p)
        presets, datas, keys = uniq(presets), uniq(datas), uniq(keys)
        sidecars = uniq(sidecars)

        self.checks = []  # (kind, path, QCheckBox)
        has_shared = False

        def add_section(title, paths, kind, owner_map, default_checked):
            nonlocal has_shared
            if not paths:
                return
            v.addWidget(QLabel(f"<b>{title}</b>"))
            for p in paths:
                shared = is_shared(owner_map[p.lower()])
                has_shared |= shared
                text = p + ("   [общие для вендора]" if shared else "")
                cb = QCheckBox(text)
                cb.setChecked(default_checked(shared))
                v.addWidget(cb)
                self.checks.append((kind, p, cb))

        add_section("Пресеты:", presets, "presets", owner, lambda sh: not sh)
        add_section("Данные вендора:", datas, "data", owner, lambda sh: not sh)
        add_section("Побочные DLL вне бандла (могут использоваться соседями):",
                    sidecars, "sidecar", owner_sc, lambda sh: False)
        add_section("Реестр (могут храниться настройки и лицензии):",
                    keys, "key", owner, lambda sh: False)

        daw_info = daw_info or {}
        daw_items = uniq(daw_info.get("fl_items", []))
        daw_inis = uniq(daw_info.get("reaper_inis", []))
        if daw_items or daw_inis:
            v.addWidget(QLabel("<b>Кэши DAW:</b>"))
            for p in daw_items:
                cb = QCheckBox(p + "   [FL Studio: Plugin database]")
                cb.setChecked(True)
                v.addWidget(cb)
                self.checks.append(("daw", p, cb))
            for f in daw_inis:
                cb = QCheckBox(f + "   [REAPER: убрать записи плагина, файл бэкапится]")
                cb.setChecked(True)
                v.addWidget(cb)
                self.checks.append(("dawini", f, cb))

        if not self.checks:
            v.addWidget(QLabel("Связанных файлов не найдено — удаляется только бандл."))
        if has_shared:
            warn = QLabel("⚠ В списке есть общие данные вендора: они используются и "
                          "другими его плагинами, которые останутся в системе. "
                          "Отмечай такие пункты, только если хочешь удалить их для всех.")
            warn.setWordWrap(True)
            warn.setStyleSheet(f"color: {theme.LANE_2};")
            v.addWidget(warn)
        reg_note = QLabel("Ключи реестра по умолчанию не трогаем — в них могут быть "
                          "лицензии. Отметь вручную, если уверен.")
        reg_note.setWordWrap(True)
        reg_note.setStyleSheet(f"color: {theme.MUTED};")
        v.addWidget(reg_note)
        v.addStretch(1)

        self.backup_chk = QCheckBox("Создать ZIP-бэкап перед удалением (рекомендуется)")
        self.backup_chk.setChecked(True)
        v.addWidget(self.backup_chk)
        self.perm_chk = QCheckBox("Удалить навсегда, мимо корзины (безвозвратно!)")
        self.perm_chk.setStyleSheet(f"color: {theme.LANE_2};")
        v.addWidget(self.perm_chk)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("Удалить (с бэкапом)")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)

    def selections(self):
        paths = [p for kind, p, cb in self.checks
                 if kind in ("presets", "data", "sidecar", "daw") and cb.isChecked()]
        keys = [p for kind, p, cb in self.checks if kind == "key" and cb.isChecked()]
        inis = [p for kind, p, cb in self.checks if kind == "dawini" and cb.isChecked()]
        return (paths, keys, inis,
                self.backup_chk.isChecked(), self.perm_chk.isChecked())


# --------------------------- диалог восстановления ---------------------------

class RestoreDialog(QDialog):
    """Журнал операций: что удаляли, где бэкап, кнопка восстановления."""

    def __init__(self, parent=None, changed_cb=None):
        super().__init__(parent)
        self.setWindowTitle("Журнал удаления и восстановление")
        self.resize(820, 420)
        self.changed_cb = changed_cb
        v = QVBoxLayout(self)
        self.table = QTableWidget(0, 4, self)
        self.table.setHorizontalHeaderLabels(["Дата", "Объект", "Статус", "Бэкап"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.table)
        h = QHBoxLayout()
        self.btn_restore = QPushButton("Восстановить выбранное из бэкапа")
        btn_close = QPushButton("Закрыть")
        h.addWidget(self.btn_restore)
        h.addWidget(btn_close)
        v.addLayout(h)
        self.btn_restore.clicked.connect(self.on_restore)
        btn_close.clicked.connect(self.reject)
        self.ops = []
        self.reload()

    def reload(self):
        ops = cleaner.load_journal().get("operations", [])
        self.ops = ops
        self.table.setRowCount(len(ops))
        for i, op in enumerate(ops):
            backup_ok = Path(op.get("backup_zip", "")).exists()
            for c, val in enumerate([op.get("timestamp", ""), op.get("plugin", ""),
                                     op.get("status", ""),
                                     "есть" if backup_ok else "НЕТ"]):
                self.table.setItem(i, c, QTableWidgetItem(str(val)))

    def on_restore(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.ops):
            return
        op = self.ops[row]
        if not op.get("backup_zip") or not Path(op.get("backup_zip")).exists():
            QMessageBox.warning(
                self, "Нет бэкапа",
                "Эта операция выполнялась без ZIP-бэкапа — восстановить из "
                "журнала нельзя.\nФайлы могли остаться в корзине Windows.")
            return
        if not QMessageBox.question(
                self, "Восстановление",
                f"Восстановить «{op.get('plugin')}» из бэкапа?\n"
                f"Файлы вернутся на прежние места, ключи реестра будут импортированы."
        ) == QMessageBox.Yes:
            return
        prog = QProgressDialog("Восстановление…", None, 0, 0, self)
        prog.show()
        QApplication.processEvents()
        ok, errors = cleaner.restore_operation(op)
        prog.close()
        cleaner.mark_restored(op["id"])
        if ok:
            QMessageBox.information(self, "Готово", "Восстановлено из бэкапа.")
        else:
            QMessageBox.warning(self, "Готово с ошибками", "\n".join(errors))
        self.reload()
        if self.changed_cb:
            self.changed_cb()


# ------------------------------- главное окно -------------------------------

class MainWindow(QMainWindow):
    def __init__(self, scan_on_start=True):
        super().__init__()
        self.setWindowTitle("VST3 Manager")
        self.resize(1150, 720)
        self.report = None
        self.worker = None

        central = BloomCanvas()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 10)
        root.setSpacing(10)

        top = QHBoxLayout()
        self.btn_scan = QPushButton("Пересканировать")
        self.btn_delete = QPushButton("Удалить выбранное")
        self.btn_restore = QPushButton("Журнал / Восстановить…")
        self.btn_export = QPushButton("Сохранить отчёт")
        self.btn_admin = QPushButton("Перезапуск от админа")
        self.btn_restore.setProperty("variant", "secondary")
        self.btn_export.setProperty("variant", "secondary")
        self.btn_admin.setProperty("variant", "secondary")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск по имени или вендору…")
        for w in (self.btn_scan, self.btn_delete, self.btn_restore,
                  self.btn_export, self.btn_admin, self.search):
            top.addWidget(w)
        root.addLayout(top)

        self.admin_label = QLabel()
        root.addWidget(self.admin_label)

        split = QSplitter()
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Плагин / вендор", "Размер", "Статус"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self.on_anchor)
        split.addWidget(self.tree)
        split.addWidget(self.details)
        split.setSizes([650, 500])
        root.addWidget(split, 1)

        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_delete.clicked.connect(self.on_delete)
        self.btn_restore.clicked.connect(self.on_restore)
        self.btn_export.clicked.connect(self.on_export)
        self.btn_admin.clicked.connect(self.on_relaunch_admin)
        self.tree.itemSelectionChanged.connect(self.on_select)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        self.search.textChanged.connect(lambda _t: self.populate())

        self.update_admin_label()
        if scan_on_start:
            self.start_scan()

    # ----- служебное -----

    def update_admin_label(self):
        if is_admin():
            self.admin_label.setText("✅ Права администратора: есть — можно удалять из Program Files")
            self.admin_label.setStyleSheet(f"color: {theme.UMBER}; font-weight: 500;")
            self.btn_admin.setVisible(False)
        else:
            self.admin_label.setText("⚠ Нет прав администратора: удаление из Program Files будет падать. "
                                     "Нажми «Перезапуск от админа».")
            self.admin_label.setStyleSheet(f"color: {theme.LANE_2}; font-weight: 500;")

    def on_relaunch_admin(self):
        if relaunch_as_admin():
            self.close()

    def on_anchor(self, url):
        target = unquote(url.toString())
        if target.startswith("explorer:"):
            open_in_explorer(target[len("explorer:"):])

    def on_double_click(self, item, _col=0):
        data = item.data(0, Qt.UserRole)
        if data and data["kind"] == "plugin":
            open_in_explorer(data["entry"]["path"])

    def on_export(self):
        if not self.report:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт",
                                              "vst3_report.json", "JSON (*.json)")
        if path:
            Path(path).write_text(
                json.dumps(self.report, ensure_ascii=False, indent=2),
                encoding="utf-8")
            self.statusBar().showMessage(f"Отчёт сохранён: {path}")

    # ----- сканирование -----

    def start_scan(self):
        self.btn_scan.setEnabled(False)
        self.btn_delete.setEnabled(False)
        self.statusBar().showMessage("Сканирование…")
        self.worker = ScanWorker()
        self.worker.progress.connect(
            lambda m: self.statusBar().showMessage(f"Сканирование: {m}"))
        self.worker.finished_scan.connect(self.on_scan_done)
        self.worker.start()

    def on_scan_done(self, rep):
        self.btn_scan.setEnabled(True)
        if rep.get("error"):
            QMessageBox.critical(self, "Ошибка сканирования", rep["error"])
        self.apply_report(rep)

    def apply_report(self, rep):
        self.report = rep
        self.populate()
        self.details.setHtml(
            f"<p style='color:{theme.MUTED}'>Выбери плагин или вендора слева — "
            f"здесь появится карточка со всеми связями и «хвостами».</p>")
        daws = ", ".join(rep.get("daw_caches", {})) or "не найдены"
        self.statusBar().showMessage(
            f"Плагинов: {rep['plugin_count']} | Размер: "
            f"{fmt_size(rep.get('total_size_bytes', 0))} | "
            f"Кэши DAW: {daws} | Скан от {rep.get('generated', '')}")

    def populate(self):
        self.tree.clear()
        if not self.report:
            return
        flt = self.search.text().strip().lower()
        groups = {}
        for e in self.report["plugins"]:
            groups.setdefault(e["vendor"] or "(без вендора)", []).append(e)
        orphans = self.report.get("orphans") or []
        if orphans:
            groups["(сироты — плагины уже удалены)"] = orphans
        for vendor in sorted(groups, key=str.lower):
            items = sorted(groups[vendor], key=lambda x: x["name"].lower())
            if flt and flt not in vendor.lower() \
                    and not any(flt in e["name"].lower() for e in items):
                continue
            vnode = QTreeWidgetItem([vendor,
                                     fmt_size(sum(e["size_bytes"] for e in items)),
                                     f"{len(items)} шт."])
            vnode.setTextAlignment(1, int(Qt.AlignRight | Qt.AlignVCenter))
            f = vnode.font(0)
            f.setBold(True)
            vnode.setFont(0, f)
            vnode.setData(0, Qt.UserRole, {"kind": "vendor", "plugins": items})
            for e in items:
                label = RISK_LABEL.get(e["risk"], "")
                child = QTreeWidgetItem([e["name"], fmt_size(e["size_bytes"]), label])
                child.setTextAlignment(1, int(Qt.AlignRight | Qt.AlignVCenter))
                if label:
                    if e["risk"] == "shared-data":
                        color = theme.LANE_2
                    elif e["risk"] == "orphan":
                        color = theme.MUTED
                    else:
                        color = theme.ACCENT
                    child.setForeground(2, QBrush(QColor(color)))
                child.setData(0, Qt.UserRole, {"kind": "plugin", "entry": e})
                vnode.addChild(child)
            self.tree.addTopLevelItem(vnode)
        self.tree.expandAll()

    # ----- карточки -----

    def on_select(self):
        item = self.tree.currentItem()
        if not item:
            return
        data = item.data(0, Qt.UserRole)
        if not data:
            return
        self.btn_delete.setEnabled(True)
        if data["kind"] == "plugin":
            self.details.setHtml(self.plugin_card(data["entry"]))
        else:
            self.details.setHtml(self.vendor_card(data["plugins"]))

    def plugin_card(self, e):
        rel = e["related"]
        esc = html.escape

        def block(paths, empty="— нет"):
            if not paths:
                return empty
            return "<br>".join("• " + esc(p) for p in paths)

        chips = {"clean": (theme.PAPER_3, theme.UMBER, "только бандл"),
                 "has-related": (theme.ACCENT_WASH, theme.ACCENT, "есть хвосты"),
                 "shared-data": (theme.ACCENT_WASH, theme.LANE_2,
                                 "общие данные вендора"),
                 "orphan": (theme.PAPER_3, theme.MUTED, "сирота")}
        bg, fg, txt = chips.get(e["risk"], (theme.PAPER_3, theme.UMBER, ""))
        ver = e.get("version") or ""
        h = [f"<h2 style='color:{theme.INK}; margin-bottom:2px;'>{esc(e['name'])}</h2>",
             f"<p style='margin-top:2px;'>"
             f"<span style='background-color:{bg}; color:{fg};'>&nbsp;{txt}&nbsp;</span>"
             + (f" &nbsp;<span style='color:{theme.MUTED}'>v{esc(ver)}</span>"
                if ver else "") + "</p>",
             f"<p><b>Вендор:</b> {esc(e['vendor'] or '—')}</p>",
             f"<p><b>Путь:</b> {esc(e['path'])}</p>",
             f"<p><b>Размер:</b> {fmt_size(e['size_bytes'])} "
             f"({e['file_count']} файлов)</p>",
             f"<p><a href='explorer:{quote(e['path'])}' "
             f"style='color:{theme.ACCENT};'>Открыть папку в проводнике ↗</a></p>"]
        for wmsg in e.get("warnings", []):
            h.append(f"<p style='color:{theme.LANE_2}'><b>⚠</b> {esc(wmsg)}</p>")
        h += [f"<h4 style='color:{theme.MUTED}'>Связанные файлы (хвосты)</h4>",
              f"<p><b>Пресеты:</b><br>{block(rel['presets'])}</p>",
              f"<p><b>Данные вендора:</b><br>{block(rel['vendor_data'])}</p>",
              f"<p><b>Реестр:</b><br>{block(rel['registry'])}</p>"]
        side = e.get("sidecar_dlls") or []
        h.append(f"<p><b>Побочные DLL (вне бандла):</b><br>{block(side)}</p>")
        return "".join(h)

    def vendor_card(self, items):
        esc = html.escape
        total = sum(e["size_bytes"] for e in items)
        shared = sum(1 for e in items if e["risk"] == "shared-data")
        h = [f"<h2 style='color:{theme.INK}'>{esc(items[0]['vendor'] or '(без вендора)')}</h2>",
             f"<p><b>Плагинов:</b> {len(items)} &nbsp;&nbsp; "
             f"<b>Суммарный размер:</b> {fmt_size(total)}</p>"]
        if shared:
            h.append(f"<p style='color:{theme.LANE_2}'><b>⚠</b> У {shared} плагинов общие "
                     f"данные вендора — при удалении программа спросит отдельно.</p>")
        h.append("<h4>Плагины</h4><p>" + "<br>".join(
            f"• {esc(e['name'])} — {fmt_size(e['size_bytes'])}" for e in items) + "</p>")
        return "".join(h)

    # ----- удаление и восстановление -----

    def on_delete(self):
        item = self.tree.currentItem()
        data = item.data(0, Qt.UserRole) if item else None
        if not data:
            return
        entries = data["plugins"] if data["kind"] == "vendor" else [data["entry"]]
        if not self.report["plugins"]:
            return
        daw_info = daw.mentions(entries)
        dlg = DeleteDialog(entries, self.report, daw_info, self)
        if not dlg.exec():
            return
        paths, keys, daw_inis, do_backup, permanent = dlg.selections()
        if permanent:
            r = QMessageBox.warning(
                self, "Безвозвратное удаление",
                f"Удалить НАВСЕГДА, мимо корзины?\n\nПлагинов: {len(entries)}.\n"
                f"Восстановление будет НЕВОЗМОЖНО.",
                QMessageBox.Yes | QMessageBox.No)
            if r != QMessageBox.Yes:
                return
        self._execute_deletion(entries, paths, keys, daw_inis, do_backup, permanent)

    def _execute_deletion(self, entries, paths, keys, daw_inis=None,
                          do_backup=True, permanent=False):
        # проверка прав для Program Files
        pf = os.environ.get("ProgramFiles", r"C:\Program Files").lower()
        pf86 = os.environ.get("ProgramFiles(x86)", "").lower()
        needs_admin = not is_admin() and any(
            e["path"].lower().startswith((pf, pf86)) for e in entries)
        if needs_admin:
            box = QMessageBox(self)
            box.setWindowTitle("Нужны права администратора")
            box.setText("Плагины лежат в Program Files — без прав администратора "
                        "удаление завершится ошибкой.\n\nПерезапустить программу "
                        "от имени администратора?")
            b_yes = box.addButton("Перезапустить от админа", QMessageBox.AcceptRole)
            b_go = box.addButton("Продолжить всё равно", QMessageBox.DestructiveRole)
            b_no = box.addButton("Отмена", QMessageBox.RejectRole)
            box.exec()
            clicked = box.clickedButton()
            if clicked is b_yes:
                self.on_relaunch_admin()
                return
            if clicked is b_no:
                return

        prog = QProgressDialog("Подготовка…", None, 0, 0, self)
        prog.setWindowTitle("Удаление с бэкапом")
        prog.show()
        QApplication.processEvents()

        def progress(msg):
            prog.setLabelText(msg)
            QApplication.processEvents()

        try:
            op = cleaner.backup_and_delete(entries, paths, keys,
                                           ini_files=daw_inis, progress=progress,
                                           backup=do_backup, permanent=permanent)
        except Exception as e:
            prog.close()
            QMessageBox.critical(self, "Ошибка", str(e))
            return
        prog.close()
        if op["errors"]:
            QMessageBox.warning(self, "Удалено с ошибками",
                                "Часть объектов удалить не удалось:\n"
                                + "\n".join(op["errors"])
                                + "\n\nСовет: перезапусти от имени администратора "
                                  "и повтори — журнал и бэкап уже созданы.")
        else:
            msg = (f"Удалено объектов: {len(op['deleted_paths'])}\n"
                   f"Ключей реестра: {len(op['registry_deleted'])}\n")
            if op.get("backup_zip"):
                msg += f"Бэкап: {op['backup_zip']}"
            elif permanent:
                msg += "Режим: навсегда, мимо корзины"
            else:
                msg += "Без ZIP-бэкапа (файлы можно найти в корзине Windows)"
            QMessageBox.information(self, "Готово", msg)
        # убираем удалённое из списка мгновенно, без полного пересканирования
        deleted = set(op["deleted_paths"])
        if deleted:
            self.report["plugins"] = [e for e in self.report["plugins"]
                                      if e["path"] not in deleted]
            self.report["orphans"] = [o for o in self.report.get("orphans", [])
                                      if o["path"] not in deleted]
            self.report["plugin_count"] = len(self.report["plugins"])
            self.report["total_size_bytes"] = sum(
                e["size_bytes"] for e in self.report["plugins"])
            self.populate()
            self.details.setHtml(
                f"<p style='color:{theme.MUTED}'>Выбери плагин слева — "
                f"здесь появится карточка со всеми связями и «хвостами».</p>")
            self.btn_delete.setEnabled(False)
            self.statusBar().showMessage(
                f"Плагинов: {self.report['plugin_count']} | Размер: "
                f"{fmt_size(self.report['total_size_bytes'])} | "
                f"удалено: {len(deleted)} объектов")

    def on_restore(self):
        RestoreDialog(self, changed_cb=self.start_scan).exec()
