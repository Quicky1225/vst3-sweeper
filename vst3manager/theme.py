# -*- coding: utf-8 -*-
"""Тема Cobalt для VST3 Manager — по спецификации hallmark (nutlope/hallmark),
skills/hallmark/references/themes/cobalt.md.

«Cool near-white paper ruled with hairlines»: прохладная почти-белая бумага,
волосяные линии, клавиши-кейкапы (3px нижняя кромка, нажатие утапливает),
graphite-полосы, точечная сетка поля на фоне, кобальт не больше 5% экрана.
Без градиентных кнопок, тёплых акцентов и filled-chip статусов.

Токены переведены из oklch в HEX:
  paper      oklch(98.6% 0.005 250) -> #F8FBFE
  ink        oklch(21% 0.028 262)   -> #111825
  accent     oklch(52% 0.19 258)    -> #0462D3  (кобальт)
  graphite   oklch(21% 0.01 260)    -> #16181D
"""

# — бумага и чернила —
PAPER = "#F8FBFE"
PAPER_2 = "#F0F3F6"
PAPER_3 = "#E5E8EB"
SHEET = "#FBFDFF"          # key-face: поверхность карточек
INK = "#111825"
INK_2 = "#373D48"
MUTED = "#5D646F"
RULE = "#D9DFE5"
RULE_2 = "#C2C8CF"

# — graphite-материал (тёмные полосы, максимум одна на экран) —
GRAPHITE = "#16181D"
GRAPHITE_2 = "#22252B"
GRAPHITE_INK = "#E4E8EF"
GRAPHITE_MUTED = "#949CA8"

# — кобальтовый акцент —
ACCENT = "#0462D3"
ACCENT_2 = "#7CB2FF"
ACCENT_WASH = "#DEF0FF"
ACCENT_INK = "#F7FBFF"
ACCENT_DEEP = "#0049AA"
ACCENT_EDGE = "#003E98"
ACCENT_SOFT = "rgba(4, 98, 211, 0.10)"

# — клавиши —
KEY_FACE = "#FBFDFF"
KEY_EDGE = "#B2BFD1"

# — легаси-алиасы (использовались темой Bloom в ui.py) —
UMBER = INK_2
LANE_2 = ACCENT_DEEP
RUBBER_HI = ACCENT
RUBBER = ACCENT_DEEP
RUBBER_LO = ACCENT_EDGE

FONT_STACK = "'Familjen Grotesk','IBM Plex Sans','Segoe UI',sans-serif"
MONO_STACK = "'JetBrains Mono','Cascadia Mono',Consolas,monospace"

APP_QSS = f"""
/* VST3 Manager — тема Cobalt (hallmark) */

QWidget {{
    font-family: {FONT_STACK};
    color: {INK};
    font-size: 10pt;
}}

QMainWindow, QDialog {{
    background-color: {PAPER};
}}

QLabel {{
    background: transparent;
    color: {INK_2};
}}

QToolTip {{
    background: {GRAPHITE_2}; color: {GRAPHITE_INK};
    border: 1px solid {GRAPHITE_2}; padding: 4px 8px;
}}

/* — клавиши: первичная — цельная кобальтовая, вторичная — светлая кейкап — */
QPushButton {{
    background: {ACCENT}; color: {ACCENT_INK};
    border: 1px solid {ACCENT_DEEP};
    border-bottom: 3px solid {ACCENT_EDGE};
    border-radius: 6px;
    padding: 5px 16px 6px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background: #0A67D8; }}
QPushButton:pressed {{
    background: {ACCENT_DEEP};
    border-bottom: 1px solid {ACCENT_EDGE};
    padding-top: 8px;
}}
QPushButton:disabled {{
    background: {PAPER_2}; color: {MUTED};
    border: 1px solid {RULE}; border-bottom: 3px solid {RULE};
}}

QPushButton[variant="secondary"] {{
    background: {KEY_FACE}; color: {INK};
    border: 1px solid {RULE_2};
    border-bottom: 3px solid {KEY_EDGE};
    border-radius: 6px;
    padding: 5px 14px 6px 14px;
    font-weight: 500;
}}
QPushButton[variant="secondary"]:hover {{ background: {PAPER_2}; }}
QPushButton[variant="secondary"]:pressed {{
    background: {PAPER_3};
    border-bottom: 1px solid {KEY_EDGE};
    padding-top: 8px;
}}
QPushButton[variant="secondary"]:disabled {{
    color: {MUTED}; background: {PAPER_2}; border-bottom-color: {RULE};
}}

/* — инпуты: cut-поле с приглушённой границей и кобальтовым фокусом — */
QLineEdit {{
    background: {SHEET}; border: 1px solid {RULE_2};
    border-radius: 6px; padding: 6px 14px; color: {INK};
    selection-background-color: {ACCENT}; selection-color: {ACCENT_INK};
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}

/* — карточки: волосяная рамка, радиус 8px, лёгкая тень имитируется рамкой — */
QTreeWidget {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 8px; padding: 4px; outline: none;
}}
QTreeWidget::item {{
    padding: 5px 8px; margin: 0px 4px;
    border-radius: 4px; color: {INK_2};
}}
QTreeWidget::item:hover {{ background: {PAPER_2}; }}
QTreeWidget::item:selected {{ background: {ACCENT_WASH}; color: {INK}; }}

QHeaderView::section {{
    background: transparent; color: {MUTED};
    border: none; border-bottom: 1px solid {RULE};
    padding: 8px 10px; font-weight: 500; font-size: 9pt;
}}

QTextBrowser {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 8px; padding: 10px 14px;
}}

QTableWidget {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 8px; gridline-color: transparent;
    alternate-background-color: {SHEET};
}}
QTableWidget::item {{ padding: 4px 6px; color: {INK_2}; }}
QTableWidget::item:selected {{ background: {ACCENT_WASH}; color: {INK}; }}

/* — чекбоксы — */
QCheckBox {{ color: {INK_2}; spacing: 8px; padding: 2px 0; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid {RULE_2}; background: {SHEET};
}}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QTreeWidget::indicator, QListWidget::indicator {{
    width: 15px; height: 15px; border-radius: 4px;
    border: 1px solid {RULE_2}; background: {SHEET};
}}
QTreeWidget::indicator:hover, QListWidget::indicator:hover {{
    border-color: {ACCENT};
}}
QTreeWidget::indicator:checked, QListWidget::indicator:checked {{
    background: {ACCENT}; border-color: {ACCENT};
}}
QTreeWidget::indicator:indeterminate {{
    background: {ACCENT_WASH}; border-color: {ACCENT};
}}

/* — список кастомных папок — */
QListWidget {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 8px; padding: 4px; outline: none;
}}
QListWidget::item {{ padding: 6px 8px; border-radius: 4px; color: {INK_2}; }}
QListWidget::item:selected {{ background: {ACCENT_WASH}; color: {INK}; }}

/* — разделитель панелей: волосяная линия, при наведении кобальт — */
QSplitter::handle {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(17, 24, 37, 0),
        stop:0.5 rgba(17, 24, 37, 0.22),
        stop:1 rgba(17, 24, 37, 0));
    width: 14px;
    margin: 6px 2px;
}}
QSplitter::handle:horizontal:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(4, 98, 211, 0),
        stop:0.5 rgba(4, 98, 211, 0.55),
        stop:1 rgba(4, 98, 211, 0));
}}

/* — graphite-полоса статуса (единственная тёмная полоса на экране) — */
QStatusBar {{
    background: {GRAPHITE}; color: {GRAPHITE_MUTED};
    border-top: 1px solid {GRAPHITE_2};
}}
QStatusBar::item {{ border: none; }}

/* — скроллбары: тонкие волосяные — */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 4px 3px; }}
QScrollBar::handle:vertical {{ background: {RULE_2}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 3px 4px; }}
QScrollBar::handle:horizontal {{ background: {RULE_2}; border-radius: 5px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {MUTED}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
"""
