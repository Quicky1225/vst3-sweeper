# -*- coding: utf-8 -*-
"""Тема Bloom для VST3 Manager — по спецификации hallmark (nutlope/hallmark),
skills/hallmark/references/themes/bloom.md.

Тёплый «дневной» студийный стиль: почти белая тёплая бумага, тёмно-коричневые
чернила, терракотовый акцент-«резина», pill-кнопки, карточки с радиусом 14–18px
и два неподвижных тёплых световых «блума» (верх-справа и низ-слева).

Токены переведены из oklch в HEX:
  paper  oklch(97% 0.010 72)  -> #F9F4EE
  sheet  oklch(98.7% 0.007 78) -> #FDFAF6
  ink    oklch(21% 0.024 40)  -> #221510
  muted  oklch(49% 0.020 56)  -> #6A5E56
  umber  oklch(30% 0.030 45)  -> #3B2921
  accent oklch(53% 0.145 36)  -> #AF4529  (терракота)
  lane-2 oklch(48% 0.105 28)  -> #8F433B
  rubber oklch(55% 0.150 34)  -> #B84930
"""

PAPER = "#F9F4EE"
PAPER_2 = "#F1ECE6"
PAPER_3 = "#E7E2DC"
SHEET = "#FDFAF6"
INK = "#221510"
MUTED = "#6A5E56"
UMBER = "#3B2921"
ACCENT = "#AF4529"
ACCENT_SOFT = "rgba(175, 69, 41, 0.10)"
ACCENT_WASH = "#F5E8E1"  # акцент 10% поверх sheet — для чипов в HTML-карточках
LANE_2 = "#8F433B"
RUBBER = "#B84930"
RUBBER_HI = "#C9583F"
RUBBER_LO = "#96311A"
RULE = "rgba(34, 21, 16, 0.14)"

FONT_STACK = "'Ranade','Segoe UI','Inter',sans-serif"

APP_QSS = f"""
/* VST3 Manager — тема Bloom (hallmark) */

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
    color: {UMBER};
}}

QToolTip {{
    background: {INK}; color: {PAPER};
    border: none; padding: 4px 8px;
}}

/* — первичные кнопки: терракотовая «резиновая» капа в утопленном ободе — */
QPushButton {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {RUBBER_HI}, stop:0.55 {RUBBER}, stop:1 {RUBBER_LO});
    color: #FFF6EF;
    border: 1px solid {RUBBER_LO};
    border-radius: 16px;
    padding: 7px 18px;
    font-weight: 600;
}}
QPushButton:hover {{ background: {RUBBER_HI}; }}
QPushButton:pressed {{ background: {RUBBER_LO}; }}
QPushButton:disabled {{
    background: {PAPER_3}; color: {MUTED};
    border-color: {RULE}; font-weight: 500;
}}

/* — вторичные кнопки: «листовая» пилюля — */
QPushButton[variant="secondary"] {{
    background: {SHEET}; color: {UMBER};
    border: 1px solid {RULE}; border-radius: 16px;
    padding: 7px 16px; font-weight: 500;
}}
QPushButton[variant="secondary"]:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
QPushButton[variant="secondary"]:pressed {{ background: {PAPER_2}; }}

/* — поле поиска: листовая пилюля — */
QLineEdit {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 17px; padding: 6px 16px; color: {INK};
    selection-background-color: {ACCENT}; selection-color: #FFF6EF;
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}

/* — список плагинов: лист-карточка — */
QTreeWidget {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 14px; padding: 4px; outline: none;
}}
QTreeWidget::item {{
    padding: 4px 8px; margin: 1px 6px;
    border-radius: 9px; color: {UMBER};
}}
QTreeWidget::item:hover {{ background: {PAPER_2}; }}
QTreeWidget::item:selected {{ background: {ACCENT_SOFT}; color: {INK}; }}

QHeaderView::section {{
    background: transparent; color: {MUTED};
    border: none; border-bottom: 1px solid {RULE};
    padding: 8px 10px; font-weight: 600; font-size: 9pt;
}}

/* — карточка деталей — */
QTextBrowser {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 14px; padding: 10px 14px;
}}

/* — таблица журнала — */
QTableWidget {{
    background: {SHEET}; border: 1px solid {RULE};
    border-radius: 12px; gridline-color: transparent;
    alternate-background-color: {SHEET};
}}
QTableWidget::item {{ padding: 4px 6px; color: {UMBER}; }}
QTableWidget::item:selected {{ background: {ACCENT_SOFT}; color: {INK}; }}

/* — чекбоксы выбора «хвостов» — */
QCheckBox {{ color: {UMBER}; spacing: 8px; padding: 2px 0; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border-radius: 5px;
    border: 1px solid {RULE}; background: {SHEET};
}}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QSplitter::handle {{ background: transparent; width: 12px; }}

QStatusBar {{
    background: {PAPER_2}; color: {MUTED};
    border-top: 1px solid {RULE};
}}
QStatusBar::item {{ border: none; }}

/* — скроллбары — */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 4px 3px; }}
QScrollBar::handle:vertical {{ background: {PAPER_3}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 3px 4px; }}
QScrollBar::handle:horizontal {{ background: {PAPER_3}; border-radius: 5px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {MUTED}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
"""
