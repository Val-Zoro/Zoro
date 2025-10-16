# gui.py

import os
import sys
from functools import lru_cache, partial
from typing import Optional, override

import requests
from PyQt5.QtGui import (
    QPixmap, QFont, QColor, QPainterPath, QRegion, QPen, QPainter, QIcon, QMovie,
    QFontMetrics, QGuiApplication, QMouseEvent, QShowEvent, QResizeEvent, QCloseEvent, QKeyEvent
)
from PyQt5.QtNetwork import QNetworkRequest, QNetworkAccessManager, QNetworkReply
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QStackedWidget, QSizePolicy,
    QFrame, QGraphicsDropShadowEffect, QBoxLayout, QGraphicsBlurEffect, QProgressBar, QScrollArea
)
from PyQt5.QtCore import Qt, QPoint, QTimer, QThread, pyqtSignal, QRectF, QSize, QPropertyAnimation, QObject, QUrl, \
    QBuffer, pyqtProperty, QEasingCurve

# Local Imports
import Riot
from Logger import Logger
from utils import Utils

KEY = ("-----BEGIN PUBLIC KEY-----\n"
       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqIKYJWIl6Wif397yi3P+\n"
       "YnVZ9ExhGvuUpECU+BhpnJkP1pHJldurnKfpIdGhsiTblzlFvMS5y3wdKNmtpIW7\n"
       "8KVC8bL7FwLShmMBQNkEL4GvZfgGHYbAlJOXOiWuqDk/CS28ccZyEzAkxT4WY4H2\n"
       "BWVVBPax72ksJL2oMOxYJVZg2w3P3LbWNfcrgAC1/HPVzmuYka0IDo9TevbCwccC\n"
       "yNS3GlJ6g4E7yp8RIsFyEoq7DueHuK+zkvgpmb5eLRg8Ssq9t6bCcnx6Sl2hb4n/\n"
       "5OmRNvohCFM3WpP1vAdNxrsQT8uSuExbH4g7uDT/l5+ZdpxytzEzGdvPezmPiXhL\n"
       "5QIDAQAB\n"
       "-----END PUBLIC KEY-----")

NAME = "Zoro"
VERSION = "v3.0.0-ALPHA"

MAIN_WINDOW_SIZE = (1500, 800)
LOADING_WINDOW_SIZE = (500, 300)

# --- Professional UI Style ---
# A unified design system for a modern, clean, and Valorant-inspired look.

# Enhanced Color Palette - Modern Dark Theme
BACKGROUND_COLOR = "#0F0F0F"      # Richer near-black with subtle blue undertone
PRIMARY_UI_COLOR = "#1A1A1A"      # Enhanced primary surface with better depth
SECONDARY_UI_COLOR = "#242424"    # Improved secondary surface with subtle gradient support
TERTIARY_UI_COLOR = "#2A2A2A"     # Additional surface level for hierarchy
BORDER_COLOR = "#333333"          # Softer, more modern border color
BORDER_HIGHLIGHT = "#404040"      # Highlighted border for focus states

# Enhanced Accent Colors - Valorant-inspired with modern gradients
ACCENT_COLOR = "#FF4655"          # Valorant Red - maintained for brand consistency
ACCENT_HOVER = "#FF5C6B"          # Enhanced hover state
ACCENT_PRESSED = "#E03B4A"        # Enhanced pressed state
ACCENT_GRADIENT_START = "#FF4655" # Gradient start for accent elements
ACCENT_GRADIENT_END = "#FF6B7A"   # Gradient end for accent elements
SECONDARY_ACCENT_COLOR = "#4A90E2" # Cool blue - maintained
SECONDARY_ACCENT_GRADIENT_START = "#4A90E2" # Blue gradient start
SECONDARY_ACCENT_GRADIENT_END = "#5BA0F2"   # Blue gradient end

# Success/Warning/Error Colors
SUCCESS_COLOR = "#4CAF50"         # Modern green for success states
WARNING_COLOR = "#FF9800"         # Modern orange for warnings
ERROR_COLOR = "#F44336"           # Modern red for errors

# Enhanced Text Colors
PRIMARY_TEXT_COLOR = "#FFFFFF"    # Pure white for maximum contrast and readability
SECONDARY_TEXT_COLOR = "#B3B3B3"  # Improved secondary text with better contrast
TERTIARY_TEXT_COLOR = "#808080"   # Additional text level for hierarchy
DISABLED_TEXT_COLOR = "#555555"   # Enhanced disabled text
PLACEHOLDER_TEXT_COLOR = "#707070" # Improved placeholder text visibility

# Enhanced Glass Effect (for cards and panels)
GLASS_BACKGROUND = "rgba(26, 26, 26, 0.85)"  # Enhanced semi-transparent background
GLASS_BACKGROUND_ALT = "rgba(36, 36, 36, 0.75)" # Alternative glass background
GLASS_BORDER = f"1px solid {BORDER_COLOR}"
GLASS_BORDER_HIGHLIGHT = f"1px solid {BORDER_HIGHLIGHT}"
GLASS_SHADOW_COLOR = "rgba(0, 0, 0, 0.6)"  # Enhanced shadow for better depth
GLASS_SHADOW_HIGHLIGHT = "rgba(255, 70, 85, 0.2)" # Accent-colored shadow for special elements

# Enhanced Typography System
FONT_FAMILY = "'Segoe UI', system-ui, -apple-system, sans-serif"
FONT_FAMILY_MONO = "'JetBrains Mono', 'Fira Code', 'Consolas', monospace"

# Enhanced Font styles with better hierarchy and spacing
TYPOGRAPHY = {
    "Display": {
        "font-size": "36px", "font-weight": "700", "color": PRIMARY_TEXT_COLOR,
        "line-height": "1.2", "letter-spacing": "-0.02em"
    },
    "Title": {
        "font-size": "28px", "font-weight": "700", "color": ACCENT_COLOR,
        "line-height": "1.3", "letter-spacing": "-0.01em"
    },
    "Subtitle": {
        "font-size": "20px", "font-weight": "600", "color": PRIMARY_TEXT_COLOR,
        "line-height": "1.4", "letter-spacing": "-0.005em"
    },
    "Heading": {
        "font-size": "18px", "font-weight": "600", "color": PRIMARY_TEXT_COLOR,
        "line-height": "1.4", "letter-spacing": "0em"
    },
    "Body": {
        "font-size": "15px", "font-weight": "400", "color": PRIMARY_TEXT_COLOR,
        "line-height": "1.6", "letter-spacing": "0.01em"
    },
    "BodySecondary": {
        "font-size": "14px", "font-weight": "400", "color": SECONDARY_TEXT_COLOR,
        "line-height": "1.5", "letter-spacing": "0.01em"
    },
    "Small": {
        "font-size": "12px", "font-weight": "400", "color": SECONDARY_TEXT_COLOR,
        "line-height": "1.4", "letter-spacing": "0.02em"
    },
    "Caption": {
        "font-size": "11px", "font-weight": "400", "color": TERTIARY_TEXT_COLOR,
        "line-height": "1.3", "letter-spacing": "0.03em"
    },
    "Button": {
        "font-size": "14px", "font-weight": "600", "letter-spacing": "0.02em"
    },
    "ButtonSmall": {
        "font-size": "12px", "font-weight": "600", "letter-spacing": "0.03em"
    },
    "Link": {
        "font-size": "14px", "font-weight": "500", "color": SECONDARY_ACCENT_COLOR,
        "text-decoration": "none", "letter-spacing": "0.01em"
    },
    "Code": {
        "font-family": FONT_FAMILY_MONO, "font-size": "13px", "font-weight": "400",
        "color": ACCENT_COLOR, "background": "rgba(255, 70, 85, 0.1)",
        "padding": "2px 6px", "border-radius": "4px"
    }
}

# Helper to convert typography dict to QSS string with caching
_qss_cache = {}
def to_qss(style_dict):
    # Create a hashable key from the dict
    cache_key = tuple(sorted(style_dict.items())) if style_dict else ()
    if cache_key in _qss_cache:
        return _qss_cache[cache_key]

    s = "; ".join(f"{key.replace('_', '-')}: {value}" for key, value in style_dict.items())
    # Ensure trailing semicolon so QSS blocks that include this string remain valid
    result = s + (";" if s and not s.strip().endswith(";") else "")
    _qss_cache[cache_key] = result
    return result

# Pre-built QSS strings for convenience
DISPLAY_FONT = to_qss(TYPOGRAPHY["Display"])
TITLE_FONT = to_qss(TYPOGRAPHY["Title"])
SUBTITLE_FONT = to_qss(TYPOGRAPHY["Subtitle"])
HEADING_FONT = to_qss(TYPOGRAPHY["Heading"])
TEXT_FONT = to_qss(TYPOGRAPHY["Body"])
SECONDARY_TEXT_FONT = to_qss(TYPOGRAPHY["BodySecondary"])
SMALL_TEXT_FONT = to_qss(TYPOGRAPHY["Small"])
CAPTION_FONT = to_qss(TYPOGRAPHY["Caption"])
BUTTON_FONT = to_qss(TYPOGRAPHY["Button"])
BUTTON_SMALL_FONT = to_qss(TYPOGRAPHY["ButtonSmall"])
LINK_FONT = to_qss(TYPOGRAPHY["Link"])
CODE_FONT = to_qss(TYPOGRAPHY["Code"])

_missing_asset_paths: set[str] = set()
_logged_missing_assets: set[str] = set()

@lru_cache(maxsize=128)
def _load_pixmap_from_disk(path: Optional[str]) -> Optional[QPixmap]:
    if not path:
        return None
    if not os.path.exists(path):
        _missing_asset_paths.add(path)
        return None
    pixmap = QPixmap(path)
    if pixmap.isNull():
        _missing_asset_paths.add(path)
        return None
    return pixmap


@lru_cache(maxsize=64)
def _build_placeholder_pixmap(
    size: Optional[tuple[int, int]],
    text: Optional[str],
    background: str,
    text_color: str
) -> QPixmap:
    width, height = size if size else (128, 128)
    width = max(1, width)
    height = max(1, height)
    pixmap = QPixmap(width, height)
    pixmap.fill(QColor(background))
    if text:
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        font = QFont()
        font_family = FONT_FAMILY.split(",")[0].strip().strip("'\"")
        font.setFamily(font_family)
        font.setBold(True)
        font.setPointSize(max(10, min(width, height) // 5))
        painter.setFont(font)
        painter.setPen(QColor(text_color))
        painter.drawText(pixmap.rect(), Qt.AlignCenter | Qt.TextWordWrap, text)
        painter.end()
    return pixmap


def safe_load_pixmap(
    path: Optional[str],
    size: Optional[tuple[int, int]] = None,
    placeholder_text: Optional[str] = None,
    background: str = SECONDARY_UI_COLOR,
    text_color: str = PRIMARY_TEXT_COLOR
) -> QPixmap:
    pixmap = _load_pixmap_from_disk(path)
    if pixmap:
        if size:
            return pixmap.scaled(size[0], size[1], Qt.KeepAspectRatio, Qt.SmoothTransformation)
        return pixmap
    effective_size = size if size else (128, 128)
    return _build_placeholder_pixmap(effective_size, placeholder_text, background, text_color)


def pixmap_to_bytes(pixmap: QPixmap, fmt: str = "PNG") -> bytes:
    buffer = QBuffer()
    buffer.open(QBuffer.ReadWrite)
    pixmap.save(buffer, fmt)
    return bytes(buffer.data())


def report_missing_assets(logger_instance) -> None:
    global _logged_missing_assets
    if logger_instance is None:
        return
    new_assets = sorted(_missing_asset_paths.difference(_logged_missing_assets))
    if not new_assets:
        return
    for asset in new_assets:
        try:
            logger_instance.log(2, f"Missing asset: {asset}")
        except Exception:
            pass
    _logged_missing_assets.update(new_assets)

def build_global_qss() -> str:
    return f"""
    * {{
        font-family: {FONT_FAMILY};
        color: {PRIMARY_TEXT_COLOR};
        selection-background-color: {ACCENT_COLOR};
        selection-color: {PRIMARY_TEXT_COLOR};
    }}

    /* --- Base Widgets --- */

    QWidget {{
        background-color: transparent;
    }}

    QMainWindow {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 {BACKGROUND_COLOR},
            stop: 0.3 rgba(26, 26, 26, 0.95),
            stop: 1 rgba(15, 15, 15, 0.98));
    }}

    QToolTip {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(30, 30, 30, 0.95));
        color: {PRIMARY_TEXT_COLOR};
        border: 1px solid {BORDER_COLOR};
        padding: 10px 14px;
        border-radius: 10px;
        {to_qss(TYPOGRAPHY["BodySecondary"])}
    }}

    /* --- Enhanced Buttons --- */

    QPushButton {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(30, 30, 30, 0.95));
        border: 1px solid {BORDER_COLOR};
        border-radius: 10px;
        padding: 10px 20px;
        {BUTTON_FONT}
        
    }}

    QPushButton:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {TERTIARY_UI_COLOR},
            stop: 1 rgba(40, 40, 40, 0.95));
        border-color: {BORDER_HIGHLIGHT};
        
        
    }}

    QPushButton:pressed {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 rgba(20, 20, 20, 0.95),
            stop: 1 {SECONDARY_UI_COLOR});
        border-color: {BORDER_COLOR};
        
        
    }}

    QPushButton:disabled {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(26, 26, 26, 0.9));
        color: {DISABLED_TEXT_COLOR};
        border-color: {BORDER_COLOR};
        opacity: 0.6;
    }}

    /* Primary Action Button */
    QPushButton[objectName*="Action"] {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {ACCENT_GRADIENT_START},
            stop: 1 {ACCENT_GRADIENT_END});
        color: {PRIMARY_TEXT_COLOR};
        border: none;
        font-weight: 700;
        
    }}

    QPushButton[objectName*="Action"]:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {ACCENT_HOVER},
            stop: 1 #FF6B7A);
        
        
    }}

    QPushButton[objectName*="Action"]:pressed {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {ACCENT_PRESSED},
            stop: 1 {ACCENT_COLOR});
        
        
    }}

    /* Secondary Action Button */
    QPushButton[objectName*="Secondary"] {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {SECONDARY_ACCENT_GRADIENT_START},
            stop: 1 {SECONDARY_ACCENT_GRADIENT_END});
        color: {PRIMARY_TEXT_COLOR};
        border: none;
    }}

    QPushButton[objectName*="Secondary"]:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #5BA0F2,
            stop: 1 #6BB0F2);
        
        
    }}

    /* --- Enhanced Input Fields --- */

    QLineEdit {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {PRIMARY_UI_COLOR},
            stop: 1 rgba(26, 26, 26, 0.95));
        border: 1px solid {BORDER_COLOR};
        border-radius: 10px;
        padding: 12px 16px;
        color: {PRIMARY_TEXT_COLOR};
        {to_qss(TYPOGRAPHY["Body"])}
        
    }}

    QLineEdit:focus {{
        border-color: {SECONDARY_ACCENT_COLOR};
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(30, 30, 30, 0.95));
        
    }}

    QLineEdit::placeholder {{
        color: {PLACEHOLDER_TEXT_COLOR};
        font-style: italic;
    }}

    /* --- Enhanced Progress Bar --- */

    QProgressBar {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {PRIMARY_UI_COLOR},
            stop: 1 rgba(26, 26, 26, 0.95));
        border: 1px solid {BORDER_COLOR};
        border-radius: 8px;
        height: 10px;
        text-align: center;
        color: transparent;
    }}

    QProgressBar::chunk {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {ACCENT_COLOR},
            stop: 1 {ACCENT_HOVER});
        border-radius: 6px;
        margin: 1px;
    }}

    /* --- Enhanced Scrollbars --- */

    QScrollArea {{
        background: transparent;
        border: none;
    }}

    QScrollBar:horizontal {{
        height: 12px;
        background: transparent;
        margin: 0 12px;
    }}
    QScrollBar::handle:horizontal {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(30, 30, 30, 0.95));
        border-radius: 6px;
        min-width: 50px;
        border: 1px solid {BORDER_COLOR};
    }}
    QScrollBar::handle:horizontal:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {TERTIARY_UI_COLOR},
            stop: 1 rgba(40, 40, 40, 0.95));
        border-color: {BORDER_HIGHLIGHT};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
        background: none;
        border: none;
        width: 0px;
    }}

    QScrollBar:vertical {{
        width: 12px;
        background: transparent;
        margin: 12px 0;
    }}
    QScrollBar::handle:vertical {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(30, 30, 30, 0.95));
        border-radius: 6px;
        min-height: 50px;
        border: 1px solid {BORDER_COLOR};
    }}
    QScrollBar::handle:vertical:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {TERTIARY_UI_COLOR},
            stop: 1 rgba(40, 40, 40, 0.95));
        border-color: {BORDER_HIGHLIGHT};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: none;
        border: none;
        height: 0px;
    }}

    /* --- Enhanced Cards and Panels (Glass Effect) --- */

    QWidget[objectName*="Card"],
    QWidget[objectName*="Panel"] {{
        background: {GLASS_BACKGROUND};
        border: {GLASS_BORDER};
        border-radius: 18px;
        
    }}

    QWidget[objectName*="Card"]:hover,
    QWidget[objectName*="Panel"]:hover {{
        background: {GLASS_BACKGROUND_ALT};
        border-color: {BORDER_HIGHLIGHT};
        
        
    }}

    /* --- Enhanced Specific Labels --- */

    QLabel[objectName*="Header"] {{
        {DISPLAY_FONT}
    }}

    QLabel[objectName*="Title"] {{
        {TITLE_FONT}
    }}

    QLabel[objectName*="Subtitle"] {{
        {SUBTITLE_FONT}
    }}

    QLabel[objectName*="Heading"] {{
        {HEADING_FONT}
    }}

    /* Welcome header (consistent look) */
    QLabel#WelcomeHeader {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {PRIMARY_UI_COLOR},
            stop: 1 rgba(30, 30, 30, 0.95));
        border-bottom: 1px solid {BORDER_COLOR};
        padding: 16px 24px;
        border-top-left-radius: 0px;
        border-top-right-radius: 0px;
        {to_qss(TYPOGRAPHY['Body'])}
        color: {PRIMARY_TEXT_COLOR};
    }}

    /* --- Status Labels --- */
    QLabel[objectName*="Status"] {{
        {SECONDARY_TEXT_FONT}
        padding: 4px 8px;
        border-radius: 6px;
        background: rgba(255, 70, 85, 0.1);
    }}

    QLabel[objectName*="Success"] {{
        background: rgba(76, 175, 80, 0.1);
        color: {SUCCESS_COLOR};
    }}

    QLabel[objectName*="Warning"] {{
        background: rgba(255, 152, 0, 0.1);
        color: {WARNING_COLOR};
    }}

    QLabel[objectName*="Error"] {{
        background: rgba(244, 67, 54, 0.1);
        color: {ERROR_COLOR};
    }}

    /* --- Focus and Selection States --- */
    *:focus {{
        outline: none;
    }}

    QPushButton:focus {{
        border-color: {SECONDARY_ACCENT_COLOR};
        
    }}

    QLineEdit:focus {{
        border-color: {SECONDARY_ACCENT_COLOR};
        
    }}

    /* --- Loading States --- */
    QPushButton:disabled {{
        
        opacity: 0.6;
    }}

    /* --- Success States --- */
    QPushButton[objectName*="Success"] {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {SUCCESS_COLOR},
            stop: 1 #66BB6A);
        color: white;
        border: none;
        font-weight: 700;
    }}

    QPushButton[objectName*="Success"]:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #66BB6A,
            stop: 1 #4CAF50);
        
        
    }}

    /* --- Warning States --- */
    QPushButton[objectName*="Warning"] {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 {WARNING_COLOR},
            stop: 1 #FFB74D);
        color: white;
        border: none;
        font-weight: 700;
    }}

    QPushButton[objectName*="Warning"]:hover {{
        background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
            stop: 0 #FFB74D,
            stop: 1 #FF9800);
        
        
    }}

    /* --- Animation Classes --- */
    .fade-in {{
        animation: fadeIn 0.3s ease-out;
    }}

    .slide-up {{
        animation: slideUp 0.4s ease-out;
    }}

    .pulse {{
        animation: pulse 2s infinite;
    }}

    /* --- Keyframe Animations --- */
    @keyframes fadeIn {{
        from {{
            opacity: 0;
        }}
        to {{
            opacity: 1;
        }}
    }}

    @keyframes slideUp {{
        from {{
            opacity: 0;
            
        }}
        to {{
            opacity: 1;
            
        }}
    }}

    @keyframes pulse {{
        0% {{
            box-shadow: 0 0 0 0 rgba(255, 70, 85, 0.4);
        }}
        70% {{
            box-shadow: 0 0 0 10px rgba(255, 70, 85, 0);
        }}
        100% {{
            box-shadow: 0 0 0 0 rgba(255, 70, 85, 0);
        }}
    }}

    /* --- Enhanced Context Menu --- */
    QMenu {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(26, 26, 26, 0.95));
        border: 1px solid {BORDER_COLOR};
        border-radius: 12px;
        padding: 8px;
    }}

    QMenu::item {{
        padding: 8px 16px;
        border-radius: 6px;
        margin: 2px 4px;
        color: {PRIMARY_TEXT_COLOR};
    }}

    QMenu::item:selected {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {ACCENT_COLOR},
            stop: 1 {ACCENT_HOVER});
        color: white;
    }}

    QMenu::item:pressed {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {ACCENT_PRESSED},
            stop: 1 {ACCENT_COLOR});
    }}

    QMenu::separator {{
        height: 1px;
        background: {BORDER_COLOR};
        margin: 4px 8px;
    }}

    /* --- Enhanced ComboBox --- */
    QComboBox {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {PRIMARY_UI_COLOR},
            stop: 1 rgba(26, 26, 26, 0.95));
        border: 1px solid {BORDER_COLOR};
        border-radius: 10px;
        padding: 8px 12px;
        color: {PRIMARY_TEXT_COLOR};
        {to_qss(TYPOGRAPHY["Body"])}
    }}

    QComboBox:hover {{
        border-color: {BORDER_HIGHLIGHT};
    }}

    QComboBox:focus {{
        border-color: {SECONDARY_ACCENT_COLOR};
        
    }}

    QComboBox::drop-down {{
        border: none;
        width: 20px;
    }}

    QComboBox::down-arrow {{
        image: none;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 4px solid {SECONDARY_TEXT_COLOR};
        margin-right: 8px;
    }}

    QComboBox QAbstractItemView {{
        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 {SECONDARY_UI_COLOR},
            stop: 1 rgba(26, 26, 26, 0.95));
        border: 1px solid {BORDER_COLOR};
        border-radius: 10px;
        selection-background-color: {ACCENT_COLOR};
        selection-color: white;
    }}
    """

# --- Loading Screen Class ---
class LoadingScreen(QWidget):
    main_window_ready = pyqtSignal()

    def __init__(self, auth):
        super().__init__()
        self.auth = auth

        # ---- Use new design system constants ----
        self.BG = BACKGROUND_COLOR
        self.UI1 = PRIMARY_UI_COLOR
        self.ACCENT = ACCENT_COLOR
        self.TXT = PRIMARY_TEXT_COLOR
        self.TXT2 = SECONDARY_TEXT_COLOR
        self.GLASS_BG = GLASS_BACKGROUND
        self.GLASS_BORDER = GLASS_BORDER
        self.APP_NAME = NAME

        # ---- Window basics ----
        self.setObjectName("LoadingRoot")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowOpacity(0.0)

        # Dragging
        self._dragging = False
        self._dragPos = QPoint()

        # Layout root
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        # ---- Top bar ----
        self.top_bar = QWidget(self)
        self.top_bar.setObjectName("LoadingTopBar")
        self.top_bar.setFixedHeight(40)
        tb = QHBoxLayout(self.top_bar)
        tb.setContentsMargins(10, 6, 10, 6)
        tb.setSpacing(6)

        self.title_label = QLabel(self.APP_NAME)
        self.title_label.setStyleSheet(f"{to_qss(TYPOGRAPHY['Small'])}; color: {self.TXT2};")
        
        self.drag_space = QWidget()
        self.drag_space.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        tb.addWidget(self.title_label)
        tb.addSpacing(8)
        tb.addWidget(self.drag_space, 1)

        self.minimize_btn = QPushButton("─")
        self.minimize_btn.setObjectName("WinBtn")
        self.minimize_btn.setFixedSize(34, 26)
        self.minimize_btn.setCursor(Qt.PointingHandCursor)
        self.minimize_btn.clicked.connect(self.showMinimized)
        self.minimize_btn.setToolTip("Minimize")
        tb.addWidget(self.minimize_btn, 0, Qt.AlignRight)

        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("CloseBtn")
        self.close_btn.setFixedSize(34, 26)
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.clicked.connect(self.close)
        self.close_btn.setToolTip("Close")
        tb.addWidget(self.close_btn, 0, Qt.AlignRight)

        root.addWidget(self.top_bar)

        # ---- Center area ----
        center = QWidget(self)
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addStretch(1)

        self.card = QWidget(self)
        self.card.setObjectName("LoadingCard")
        self.card.setMinimumWidth(420)
        self.card.setMaximumWidth(560)

        shadow = QGraphicsDropShadowEffect(self.card)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(GLASS_SHADOW_COLOR))
        self.card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(32, 32, 32, 32)
        card_layout.setSpacing(20)

        # Logo container with enhanced styling
        logo_container = QWidget()
        logo_container.setFixedHeight(100)
        logo_container.setStyleSheet(f"""
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                stop: 0 rgba(255, 70, 85, 0.1),
                stop: 0.5 rgba(255, 70, 85, 0.05),
                stop: 1 transparent);
            border-radius: 16px;
            margin-bottom: 8px;
        """)
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 0)

        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(self.logo_label)
        card_layout.addWidget(logo_container)

        # Enhanced title with better typography
        self.title = QLabel(self.APP_NAME)
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setStyleSheet(f"{TITLE_FONT} ")
        card_layout.addWidget(self.title)

        # Enhanced underline with gradient
        self.underline = QWidget()
        self.underline.setFixedHeight(4)
        self.underline.setFixedWidth(100)
        self.underline.setStyleSheet(f"""
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                stop: 0 {self.ACCENT},
                stop: 1 {ACCENT_HOVER});
            border-radius: 2px;
            margin: 8px auto;
        """)
        card_layout.addWidget(self.underline, 0, Qt.AlignHCenter)

        # Enhanced status container
        status_container = QWidget()
        status_container.setStyleSheet(f"""
            background: rgba(255, 255, 255, 0.02);
            border-radius: 12px;
            padding: 16px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        """)
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(12)

        self.status_label = QLabel("Initializing...")
        self.status_label.setObjectName("Status")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet(f"{TEXT_FONT} text-align: center;")
        status_layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #FF4655,
                    stop: 1 #FF6B7A);
                border-radius: 4px;
            }
        """)
        status_layout.addWidget(self.progress)

        card_layout.addWidget(status_container)

        # Enhanced tip label with better styling
        self.tip_label = QLabel("Tip: Keep the Riot Client running before logging in.")
        self.tip_label.setObjectName("Tip")
        self.tip_label.setAlignment(Qt.AlignCenter)
        self.tip_label.setWordWrap(True)
        self.tip_label.setStyleSheet(f"""
            {SECONDARY_TEXT_FONT}
            color: {self.TXT2};
            background: rgba(74, 144, 226, 0.1);
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid rgba(74, 144, 226, 0.2);
            font-style: italic;
        """)
        card_layout.addWidget(self.tip_label)

        # Enhanced retry button
        self.retry_btn = QPushButton("Retry")
        self.retry_btn.setCursor(Qt.PointingHandCursor)
        self.retry_btn.setObjectName("Action")
        self.retry_btn.setFixedHeight(40)
        self.retry_btn.setStyleSheet(f"""
            QPushButton {{
                {BUTTON_FONT}
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 {ACCENT_COLOR},
                    stop: 1 {ACCENT_HOVER});
                border: none;
                border-radius: 10px;
                padding: 0 24px;
                color: white;
                
            }}
            QPushButton:hover {{
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 {ACCENT_HOVER},
                    stop: 1 #FF6B7A);
                
                box-shadow: 0 4px 12px rgba(255, 70, 85, 0.3);
            }}
            QPushButton:pressed {{
                
                box-shadow: 0 2px 6px rgba(255, 70, 85, 0.4);
            }}
        """)
        self.retry_btn.clicked.connect(self.start_retry_timeout)
        self.retry_btn.hide()
        card_layout.addWidget(self.retry_btn, 0, Qt.AlignHCenter)

        cl.addWidget(self.card, 0, Qt.AlignHCenter)
        cl.addStretch(2)
        root.addWidget(center)

        self._apply_styles()

        # Dragging logic
        def start_drag(a0: QMouseEvent) -> None:
            if a0.button() == Qt.LeftButton:
                self._dragging = True
                self._dragPos = a0.globalPos() - self.frameGeometry().topLeft()
                a0.accept()

        def move_drag(a0: QMouseEvent) -> None:
            if self._dragging and bool(a0.buttons() & Qt.LeftButton):
                self.move(a0.globalPos() - self._dragPos)
                a0.accept()

        def end_drag(a0: QMouseEvent) -> None:
            self._dragging = False
            a0.accept()

        for w in (self.top_bar, self.drag_space):
            w.mousePressEvent = start_drag
            w.mouseMoveEvent = move_drag
            w.mouseReleaseEvent = end_drag

        # Tips rotation
        self._tips = [
            "Tip: Keep the Riot Client running for a smooth experience.",
            "Tip: You can drag the window from the top bar.",
            "Tip: Check the settings page for customization options.",
        ]
        self._tip_idx = 0
        self._tips_timer = QTimer(self)
        self._tips_timer.timeout.connect(self._rotate_tip)
        self._tips_timer.start(6000)

        self._base_logo = self._load_logo_pixmap()
        self._update_logo()

        QTimer.singleShot(0, self._first_layout_pass)
        QTimer.singleShot(50, self._fade_in)

    def _apply_styles(self):
        self.setStyleSheet(f"""
            QWidget#LoadingRoot {{
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                    stop: 0 {self.BG},
                    stop: 0.5 rgba(15, 15, 15, 0.95),
                    stop: 1 rgba(10, 10, 10, 0.98));
                border-radius: 16px;
            }}
            QWidget#LoadingTopBar {{
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 {self.UI1},
                    stop: 1 rgba(30, 30, 30, 0.95));
                border-bottom: 1px solid {BORDER_COLOR};
                border-top-left-radius: 16px;
                border-top-right-radius: 16px;
            }}
            QWidget#LoadingCard {{
                background: {self.GLASS_BG};
                border: {self.GLASS_BORDER};
                border-radius: 20px;
                
            }}
            QPushButton#WinBtn {{
                background: transparent;
                color: {self.TXT2};
                border: none;
                border-radius: 8px;
                {BUTTON_SMALL_FONT}
                
            }}
            QPushButton#WinBtn:hover {{
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 {SECONDARY_UI_COLOR},
                    stop: 1 rgba(30, 30, 30, 0.95));
                color: {self.TXT};
                
            }}
            QPushButton#CloseBtn {{
                background: transparent;
                color: {self.TXT2};
                border: none;
                border-radius: 8px;
                {BUTTON_SMALL_FONT}
                
            }}
            QPushButton#CloseBtn:hover {{
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 {self.ACCENT},
                    stop: 1 {ACCENT_HOVER});
                color: white;
                
                box-shadow: 0 4px 12px rgba(255, 70, 85, 0.3);
            }}
        """)
		
    def _first_layout_pass(self):
        self._autosize_to_content(center_on_screen=True)
        self._update_mask()

    def _autosize_to_content(self, center_on_screen=False):
        self.layout().activate()
        self.adjustSize()
        if center_on_screen:
            sc = QGuiApplication.screenAt(self.geometry().center()) or QGuiApplication.primaryScreen()
            if sc:
                self.move(sc.availableGeometry().center() - self.rect().center())
        self._update_logo()

    def _update_mask(self):
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), 12, 12)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _load_logo_pixmap(self):
        return safe_load_pixmap(
            "assets/Zoro.png",
            placeholder_text="Z",
            background=SECONDARY_UI_COLOR,
            text_color=ACCENT_COLOR
        )

    def _update_logo(self):
        if not self._base_logo: return
        card_w = self.card.width() or 480
        target = max(48, min(84, int(card_w * 0.18)))
        scaled = self._base_logo.scaled(target, target, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.logo_label.setPixmap(scaled)

    def _fade_in(self):
        anim = QPropertyAnimation(self, b"windowOpacity", self)
        anim.setDuration(300)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start(QPropertyAnimation.DeleteWhenStopped)

    def finish_loading(self):
        anim = QPropertyAnimation(self, b"windowOpacity", self)
        anim.setDuration(300)
        anim.setStartValue(self.windowOpacity())
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.InCubic)
        anim.finished.connect(self._on_fade_out_done)
        anim.start(QPropertyAnimation.DeleteWhenStopped)

    def _on_fade_out_done(self):
        self.close()
        self.main_window_ready.emit()

    def showEvent(self, a0: QShowEvent) -> None:
        super().showEvent(a0)
        self._autosize_to_content(center_on_screen=True)

    def resizeEvent(self, a0: QResizeEvent) -> None:
        super().resizeEvent(a0)
        self._update_mask()
        self._update_logo()

    def keyPressEvent(self, a0: QKeyEvent) -> None:
        if a0.key() == Qt.Key_Escape:
            self.close()
        super().keyPressEvent(a0)

    def closeEvent(self, a0: QCloseEvent) -> None:
        self._tips_timer.stop()
        super().closeEvent(a0)

    def _rotate_tip(self):
        self._tip_idx = (self._tip_idx + 1) % len(self._tips)
        self.tip_label.setText(self._tips[self._tip_idx])

    def update_status(self, message):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"{TEXT_FONT}; color: {self.TXT2};")
        self.retry_btn.hide()
        self.progress.show()

    def show_error(self, message):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"{TEXT_FONT}; color: {ACCENT_COLOR};")
        self.progress.hide()
        self.retry_btn.show()

    def set_message(self, message):
        self.show_error(message)

    def clear_error(self):
        self.update_status("Retrying...")

    def retry_login(self):
        self.update_status("Retrying login...")
        try:
            if self.auth.log_in():
                init_game_loader(self.auth.headers, self.auth.logger, self.auth.puuid, self.auth.port, self.auth.encoded_pass, self.auth)
                self.finish_loading()
            else:
                self.show_error("Login Failed. Please check your credentials and ensure the Riot Client is running.")
        except Exception as e:
            self.show_error(f"An error occurred: {e}")

    def start_retry_timeout(self):
        self.retry_btn.setEnabled(False)
        self.retry_login()
        QTimer.singleShot(1500, lambda: self.retry_btn.setEnabled(True))


# --- Main Window Class --
class MainWindow(QMainWindow):
    def __init__(self, account_name="Player#0000"):
        super().__init__()
        self.setVisible(False)

        self.setWindowTitle(NAME)
        self.resize(*MAIN_WINDOW_SIZE)
        self.setMinimumSize(1000, 600)

        self.setWindowFlags(Qt.FramelessWindowHint)
        self._isDragging = False
        self._dragPos = QPoint()

        self.set_rounded_corners(radius=16)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(45)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(GLASS_SHADOW_COLOR))
        self.setGraphicsEffect(shadow)

        self.setStyleSheet(f"""
            QMainWindow {{
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                    stop: 0 {BACKGROUND_COLOR},
                    stop: 0.3 rgba(26, 26, 26, 0.95),
                    stop: 1 rgba(15, 15, 15, 0.98));
            }}
        """)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Enhanced Top Bar ---
        self.top_bar = QWidget()
        self.top_bar.setObjectName("TopBar")
        self.top_bar.setStyleSheet(f"""
            QWidget#TopBar {{
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 {PRIMARY_UI_COLOR},
                    stop: 1 rgba(30, 30, 30, 0.95));
                border-bottom: 1px solid {BORDER_COLOR};
                border-top-left-radius: 16px;
                border-top-right-radius: 16px;
            }}
        """)
        top_bar_layout = QHBoxLayout(self.top_bar)
        top_bar_layout.setContentsMargins(20, 12, 16, 12)
        top_bar_layout.setSpacing(16)

        # App Icon and Name
        app_info_layout = QHBoxLayout()
        app_info_layout.setContentsMargins(0,0,0,0)
        app_info_layout.setSpacing(10)
        
        icon_label = QLabel()
        icon_pixmap = safe_load_pixmap(
            "assets/Zoro.png",
            size=(28, 28),
            placeholder_text="Z",
            background=SECONDARY_UI_COLOR,
            text_color=PRIMARY_TEXT_COLOR
        )
        icon_label.setPixmap(icon_pixmap)
        app_info_layout.addWidget(icon_label)

        app_name_label = QLabel(NAME)
        app_name_label.setStyleSheet(f"{to_qss(TYPOGRAPHY['Subtitle'])}; color: {ACCENT_COLOR};")
        app_info_layout.addWidget(app_name_label)
        top_bar_layout.addLayout(app_info_layout)

        top_bar_layout.addStretch(1)

        # Enhanced Navigation
        nav_layout = QHBoxLayout()
        nav_layout.setContentsMargins(0,0,0,0)
        nav_layout.setSpacing(4)
        self.navButtons = []
        self.pages = QStackedWidget()
        categories = ["Main", "Stats", "Shop", "Settings"]
        for i, cat in enumerate(categories):
            btn = QPushButton(cat)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setFixedHeight(36)
            btn.setStyleSheet(f"""
                QPushButton#NavButton {{
                    background: transparent;
                    border: none;
                    padding: 8px 20px;
                    color: {SECONDARY_TEXT_COLOR};
                    {BUTTON_FONT}
                    border-radius: 8px;
                    
                }}
                QPushButton#NavButton:hover {{
                    color: {PRIMARY_TEXT_COLOR};
                    background: rgba(255, 255, 255, 0.05);
                    
                }}
                QPushButton#NavButton:checked {{
                    color: {ACCENT_COLOR};
                    font-weight: 700;
                    background: rgba(255, 70, 85, 0.1);
                    border-bottom: 2px solid {ACCENT_COLOR};
                }}
                QPushButton#NavButton:checked:hover {{
                    background: rgba(255, 70, 85, 0.15);
                }}
            """)
            if i == 0: btn.setChecked(True)
            btn.clicked.connect(partial(self.changePage, i))
            if cat == "Shop": btn.clicked.connect(self.on_shop_clicked)
            nav_layout.addWidget(btn)
            self.navButtons.append(btn)
        top_bar_layout.addLayout(nav_layout)

        # Enhanced navigation indicator
        self.nav_indicator = QWidget(self.top_bar)
        self.nav_indicator.setObjectName("NavIndicator")
        self.nav_indicator.setFixedHeight(4)
        self.nav_indicator.setStyleSheet(f"""
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                stop: 0 {ACCENT_COLOR},
                stop: 1 {ACCENT_HOVER});
            border-radius: 2px;
            
        """)
        self.nav_indicator.setGeometry(0, self.top_bar.height() - 4, 0, 4)
        self.nav_indicator.hide()

        top_bar_layout.addStretch(1)

        # Enhanced Window Controls
        win_controls_layout = QHBoxLayout()
        win_controls_layout.setContentsMargins(0,0,0,0)
        win_controls_layout.setSpacing(6)

        minimize_btn = QPushButton("─")
        minimize_btn.setObjectName("WinBtn")
        minimize_btn.setFixedSize(40, 32)
        minimize_btn.clicked.connect(self.showMinimized)

        self.max_btn = QPushButton("▢")
        self.max_btn.setObjectName("WinBtn")
        self.max_btn.setFixedSize(40, 32)
        self.max_btn.clicked.connect(self.toggle_max_restore)

        exit_btn = QPushButton("✕")
        exit_btn.setObjectName("CloseBtn")
        exit_btn.setFixedSize(40, 32)
        exit_btn.clicked.connect(self.close)

        for btn in [minimize_btn, self.max_btn, exit_btn]:
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    color: {SECONDARY_TEXT_COLOR};
                    {BUTTON_FONT}
                    
                }}
                QPushButton:hover {{
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                        stop: 0 {SECONDARY_UI_COLOR},
                        stop: 1 rgba(30, 30, 30, 0.95));
                    color: {PRIMARY_TEXT_COLOR};
                    
                    
                }}
                QPushButton:pressed {{
                    
                    
                }}
                QPushButton#CloseBtn:hover {{
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                        stop: 0 {ACCENT_COLOR},
                        stop: 1 {ACCENT_HOVER});
                    color: white;
                    
                }}
            """)
        win_controls_layout.addWidget(minimize_btn)
        win_controls_layout.addWidget(self.max_btn)
        win_controls_layout.addWidget(exit_btn)
        top_bar_layout.addLayout(win_controls_layout)

        # Dragging and double-click to maximize
        self.top_bar.mousePressEvent = self.top_bar_mousePressEvent
        self.top_bar.mouseMoveEvent = self.top_bar_mouseMoveEvent
        self.top_bar.mouseReleaseEvent = self.top_bar_mouseReleaseEvent
        self.top_bar.mouseDoubleClickEvent = self.top_bar_mouseDoubleClickEvent

        main_layout.addWidget(self.top_bar)

        # --- Enhanced Welcome Header ---
        welcome_label = QLabel(f"Welcome, {account_name}")
        welcome_label.setObjectName("WelcomeHeader")
        welcome_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        welcome_label.setStyleSheet(f"""
            QLabel#WelcomeHeader {{
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 {PRIMARY_UI_COLOR},
                    stop: 1 rgba(30, 30, 30, 0.95));
                border-bottom: 1px solid {BORDER_COLOR};
                padding: 18px 28px;
                border-top-left-radius: 0px;
                border-top-right-radius: 0px;
                {to_qss(TYPOGRAPHY['Body'])}
                color: {PRIMARY_TEXT_COLOR};
                font-weight: 600;
            }}
        """)
        main_layout.addWidget(welcome_label)

        # --- Enhanced Main Content Area ---
        content_area = QWidget()
        content_area.setStyleSheet(f"""
            background: transparent;
        """)
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(24, 24, 24, 24)
        content_layout.setSpacing(20)
        content_layout.addWidget(self.pages)
        main_layout.addWidget(content_area, 1)

        # --- Page 1: Main ---
        main_page = QWidget()
        main_page_layout = QVBoxLayout(main_page)
        main_page_layout.setContentsMargins(0, 0, 0, 0)
        main_page_layout.setSpacing(16)

        global loader_layout, loader_container, info_layout, info_container

        info_container = QWidget()
        info_container.setObjectName("InfoPanel")
        info_container.setFixedHeight(60)
        info_layout = QHBoxLayout(info_container)
        info_layout.setContentsMargins(20, 10, 20, 10)

        info_queue_label = QLabel("")
        info_queue_label.setObjectName("info_queue_label")
        info_queue_label.setStyleSheet(f"{SUBTITLE_FONT}; color: {SECONDARY_TEXT_COLOR};")
        info_layout.addWidget(info_queue_label, alignment=Qt.AlignCenter)
        main_page_layout.addWidget(info_container)

        loader_container = QWidget()
        loader_container.setObjectName("LoaderCard")
        loader_layout = QHBoxLayout(loader_container)
        loader_layout.setContentsMargins(24, 24, 24, 24)
        loader_layout.setSpacing(20)
        
        # Example content for loader card
        loader_layout.addWidget(QLabel(""))

        main_page_layout.addWidget(loader_container, 1)
        self.pages.addWidget(main_page)

        # --- Page 2: Stats (Placeholder) ---
        stats_page = QWidget()
        stats_layout = QVBoxLayout(stats_page)
        stats_label = QLabel("Stats Page")
        stats_label.setAlignment(Qt.AlignCenter)
        stats_label.setStyleSheet(DISPLAY_FONT)
        stats_layout.addWidget(stats_label)
        self.pages.addWidget(stats_page)

        # --- Page 3: Shop ---
        shop_page = QWidget()
        shop_layout = QVBoxLayout(shop_page)
        shop_layout.setContentsMargins(0, 0, 0, 0)
        shop_layout.setSpacing(12)

        shop_header = QLabel("Shop")
        shop_header.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        shop_header.setStyleSheet(f"{to_qss(TYPOGRAPHY['Title'])}; color: {ACCENT_COLOR}; padding: 12px 16px;")
        shop_layout.addWidget(shop_header)

        # Scrollable area for shop items
        shop_scroll = QScrollArea()
        shop_scroll.setWidgetResizable(True)
        shop_scroll.setFrameShape(QFrame.NoFrame)

        self.shop_items_widget = QWidget()
        self.shop_items_layout = QVBoxLayout(self.shop_items_widget)
        self.shop_items_layout.setContentsMargins(16, 16, 16, 16)
        self.shop_items_layout.setSpacing(12)
        self.shop_items_layout.addStretch(1)  # keep some space at the end

        shop_scroll.setWidget(self.shop_items_widget)
        shop_layout.addWidget(shop_scroll)

        self.pages.addWidget(shop_page)

        # --- Page 4: Settings (Placeholder) ---
        settings_page = QWidget()
        settings_layout = QVBoxLayout(settings_page)
        settings_label = QLabel("Settings Page")
        settings_label.setAlignment(Qt.AlignCenter)
        settings_label.setStyleSheet(DISPLAY_FONT)
        settings_layout.addWidget(settings_label)
        self.pages.addWidget(settings_page)

        # Apply global styles for consistent look
        try:
            # apply_global_styles appends additional rules to the window stylesheet
            self.apply_global_styles()
        except Exception:
            pass

        # Initial state
        self.changePage(0)
        QTimer.singleShot(100, self._fade_in)
        report_missing_assets(globals().get("logger"))
        self.show()
        
    def set_rounded_corners(self, radius):
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _fade_in(self):
        self.setWindowOpacity(0.0)
        self.setVisible(True)
        anim = QPropertyAnimation(self, b"windowOpacity", self)
        anim.setDuration(300)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start(QPropertyAnimation.DeleteWhenStopped)

    def changePage(self, index):
        for i, btn in enumerate(self.navButtons):
            btn.setChecked(i == index)
        self.pages.setCurrentIndex(index)
        self.update_nav_indicator()


    def toggle_max_restore(self):
        if self.isMaximized():
            self.showNormal()
            self.max_btn.setToolTip("Maximize")
            self.max_btn.setText("▢")
            self.set_rounded_corners(radius=12)
        else:
            self.showMaximized()
            self.max_btn.setToolTip("Restore")
            self.max_btn.setText("❐")
            # Avoid cutting edges with rounded mask on maximize (optional: square corners)
            self.set_rounded_corners(radius=0)

    def top_bar_mousePressEvent(self, a0: QMouseEvent) -> None:
        if a0.button() == Qt.LeftButton:
            self._isDragging = True
            self._dragPos = a0.globalPos() - self.frameGeometry().topLeft()
            a0.accept()

    def top_bar_mouseMoveEvent(self, a0: QMouseEvent) -> None:
        if self._isDragging and bool(a0.buttons() & Qt.LeftButton):
            if self.isMaximized():  # Prevent dragging when maximized
                self.toggle_max_restore()
                self._dragPos = QPoint(self.width() // 2, a0.pos().y())
            self.move(a0.globalPos() - self._dragPos)
            a0.accept()

    def top_bar_mouseReleaseEvent(self, a0: QMouseEvent) -> None:
        self._isDragging = False
        a0.accept()

    def top_bar_mouseDoubleClickEvent(self, a0: QMouseEvent) -> None:
        if a0.button() == Qt.LeftButton:
            self.toggle_max_restore()
        a0.accept()

    def keyPressEvent(self, a0: QKeyEvent) -> None:
        if a0.key() == Qt.Key_Escape:
            self.close()
        super().keyPressEvent(a0)

    # ---------------------------------
    # Behavior Helpers
    # ---------------------------------
    @override
    def resizeEvent(self, a0):
        # Preserve rounded corners during resize and keep nav indicator under active button
        if self.isMaximized():
            self.set_rounded_corners(radius=0)
        else:
            self.set_rounded_corners(radius=12)
        self.update_nav_indicator()
        super().resizeEvent(a0)

    def update_nav_indicator(self):
        # Position the indicator under the active nav button
        try:
            active_btn = self.navButtons[self.pages.currentIndex()]
        except Exception:
            return

        # Compute geometry in top_bar coords
        btn_pos = active_btn.mapTo(self.top_bar, QPoint(0, 0))
        x = btn_pos.x() + 8
        width = max(0, active_btn.width() - 16)
        y = self.top_bar.height() - 3  # bottom of top bar
        self.nav_indicator.setGeometry(x, y, width, 3)
        self.nav_indicator.show()

    # Preserve dragging from top bar only (already handled via injected handlers on top_bar)

    # ---------------------------------
    # Shop Loading
    # ---------------------------------
    def show_shop_loading(self):
        self._clear_shop_layout()

        loading_label = QLabel("Loading shop...")
        loading_label.setStyleSheet(f"""
            QLabel {{
                font-size: 16px;
                color: {PRIMARY_TEXT_COLOR};
                padding: 24px 32px;
                background: {GLASS_BACKGROUND};
                border: {GLASS_BORDER};
                border-radius: 12px;
            }}
        """)
        loading_label.setAlignment(Qt.AlignCenter)
        self.shop_items_layout.addWidget(loading_label)

    def _clear_shop_layout(self):
        """Helper method to clear shop layout and properly cleanup widgets"""
        while self.shop_items_layout.count():
            child = self.shop_items_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def process_shop(self):
        while self.shop_items_layout.count():
            child = self.shop_items_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        riot_shop = Riot.Shop(auth, logger)
        shop_items = riot_shop.get_daily_shop()
        currency = riot_shop.get_currency()

        currency_widget = QWidget()
        currency_layout = QHBoxLayout(currency_widget)
        currency_layout.setSpacing(10)
        currency_layout.setContentsMargins(0, 0, 0, 20)

        vp_label = QLabel(f"VP: {currency.get('VP', 0):,}")
        vp_label.setStyleSheet(f"""
            color: {PRIMARY_TEXT_COLOR};
            font-size: 16px;
            font-weight: 600;
            padding: 8px 14px;
            background: {GLASS_BACKGROUND};
            border-radius: 10px;
        """)
        currency_layout.addWidget(vp_label)
        currency_layout.addStretch()
        self.shop_items_layout.addWidget(currency_widget)

        items_container = QWidget()
        items_layout = QHBoxLayout(items_container)
        items_layout.setSpacing(12)
        items_layout.setContentsMargins(0, 0, 0, 0)
        self.shop_items_layout.addWidget(items_container)

        # Start image loading thread
        self._start_image_loading_thread(shop_items, items_layout)

    def add_shop_card(self, parent_layout, idx, skin_img_data, name, rarity_img_data, rarity_name, price):
        card = QWidget()
        card.setObjectName("ShopCard")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(8)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card.setFixedWidth(280)

        card.setStyleSheet(f"""
            QWidget#ShopCard {{
                background: {GLASS_BACKGROUND};
                border: {GLASS_BORDER};
                border-radius: 12px;
            }}
            QWidget#ShopCard:hover {{
                background: rgba(255, 255, 255, 0.06);
                border: 1px solid rgba(255, 255, 255, 0.12);
            }}
        """)

        # Skin image
        img_container = QWidget()
        img_container.setFixedHeight(140)
        img_container.setStyleSheet("background: rgba(0, 0, 0, 0.2); border-radius: 8px;")
        img_layout = QVBoxLayout(img_container)
        img_layout.setContentsMargins(8, 8, 8, 8)

        img_label = QLabel()
        img_label.setAlignment(Qt.AlignCenter)
        pixmap = QPixmap()
        pixmap.loadFromData(skin_img_data)
        scaled_pixmap = pixmap.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        img_label.setPixmap(scaled_pixmap)
        img_layout.addWidget(img_label)
        card_layout.addWidget(img_container)

        # Name
        name_label = QLabel(name)
        name_label.setStyleSheet(f"""
            color: {PRIMARY_TEXT_COLOR};
            font-size: 14px;
            font-weight: 700;
        """)
        name_label.setAlignment(Qt.AlignCenter)
        name_label.setWordWrap(True)
        card_layout.addWidget(name_label)

        # Rarity
        rarity_widget = QWidget()
        rarity_layout = QHBoxLayout(rarity_widget)
        rarity_layout.setSpacing(6)
        rarity_layout.setContentsMargins(0, 0, 0, 0)

        rarity_icon = QLabel()
        rarity_pixmap = QPixmap()
        rarity_pixmap.loadFromData(rarity_img_data)
        rarity_icon.setPixmap(rarity_pixmap.scaled(16, 16, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        rarity_layout.addWidget(rarity_icon)

        rarity_label = QLabel(rarity_name)
        rarity_label.setStyleSheet(f"color: {SECONDARY_TEXT_COLOR}; font-size: 12px;")
        rarity_layout.addWidget(rarity_label)
        rarity_layout.addStretch()
        card_layout.addWidget(rarity_widget)

        # Price
        cost_label = QLabel(f"{price:,} VP")
        cost_label.setStyleSheet(f"""
            color: {PRIMARY_TEXT_COLOR};
            font-size: 14px;
            font-weight: 700;
        """)
        cost_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(cost_label)

        parent_layout.addWidget(card)

    def on_shop_clicked(self):
        self.show_shop_loading()
        self.shop_thread = QThread()
        self.shop_worker = ShopLoaderWorker(auth, logger)
        self.shop_worker.moveToThread(self.shop_thread)
        self.shop_thread.started.connect(self.shop_worker.run)
        self.shop_worker.finished.connect(self.on_shop_loaded)
        self.shop_worker.finished.connect(self.shop_thread.quit)
        self.shop_worker.finished.connect(self.shop_worker.deleteLater)
        self.shop_thread.finished.connect(self.shop_thread.deleteLater)
        self.shop_thread.start()

    def on_shop_loaded(self, shop_items, currency):
        self._clear_shop_layout()

        # Create currency display
        currency_widget = QWidget()
        currency_layout = QHBoxLayout(currency_widget)
        currency_layout.setSpacing(10)
        currency_layout.setContentsMargins(0, 0, 0, 16)

        vp_label = QLabel(f"VP: {currency.get('VP', 0):,}")
        vp_label.setStyleSheet(f"""
            color: {PRIMARY_TEXT_COLOR};
            font-size: 16px;
            font-weight: 600;
            padding: 8px 14px;
            background: {GLASS_BACKGROUND};
            border-radius: 10px;
        """)
        currency_layout.addWidget(vp_label)
        currency_layout.addStretch()
        self.shop_items_layout.addWidget(currency_widget)

        # Create items container
        items_container = QWidget()
        items_layout = QHBoxLayout(items_container)
        items_layout.setSpacing(12)
        items_layout.setContentsMargins(0, 0, 0, 0)
        self.shop_items_layout.addWidget(items_container)

        # Start image loading thread
        self._start_image_loading_thread(shop_items, items_layout)

    def _start_image_loading_thread(self, shop_items, items_layout):
        """Helper method to start image loading thread"""
        self.shop_cards = [None] * len(shop_items)
        self.img_thread = QThread()
        self.img_worker = ImageLoaderWorker(shop_items)
        self.img_worker.moveToThread(self.img_thread)
        self.img_worker.imageLoaded.connect(lambda idx, skin, name, rarity_img, rarity_name:
                                            self.add_shop_card(items_layout, idx, skin, name, rarity_img, rarity_name,
                                                               shop_items[idx]['price']))
        self.img_thread.started.connect(self.img_worker.run)
        self.img_thread.start()

    # ---------------------------------
    # Image loading helpers
    # ---------------------------------
    def load_image(self, url, label):
        def on_finished():
            reply = manager.get(QNetworkRequest(QUrl(url)))
            reply.finished.connect(lambda: self.handle_image_response(reply, label))

        manager = QNetworkAccessManager()
        QTimer.singleShot(0, on_finished)

    def handle_image_response(self, reply, label):
        if reply.error() == QNetworkReply.NoError:
            data = reply.readAll()
            pixmap = QPixmap()
            pixmap.loadFromData(data)
            scaled_pixmap = pixmap.scaled(180, 180, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            label.setPixmap(scaled_pixmap)
        reply.deleteLater()

    # ---------------------------------
    # Global styles for a clean look
    # ---------------------------------
    def apply_global_styles(self):
        self.setStyleSheet(self.styleSheet() + f"""
            /* Navigation buttons (center) */
            QPushButton#NavButton {{
                background-color: transparent;
                color: {SECONDARY_TEXT_COLOR};
                border: none;
                padding: 10px 16px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 700;
            }}
            QPushButton#NavButton:checked {{
                color: {PRIMARY_TEXT_COLOR};
                background-color: rgba(255, 255, 255, 0.06);
            }}
            QPushButton#NavButton:hover {{
                background-color: rgba(255, 255, 255, 0.08);
                color: {PRIMARY_TEXT_COLOR};
            }}
            QPushButton#NavButton:pressed {{
                background-color: rgba(255, 255, 255, 0.12);
            }}

            /* Active nav indicator strip */
            QWidget#NavIndicator {{
                background: {ACCENT_COLOR};
                border-radius: 2px;
            }}

            /* Window control buttons */
            QPushButton#WinBtn {{
                background: transparent;
                color: {SECONDARY_TEXT_COLOR};
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 700;
            }}
            QPushButton#WinBtn:hover {{
                background-color: rgba(255, 255, 255, 0.10);
                color: {PRIMARY_TEXT_COLOR};
            }}
            QPushButton#WinBtn:pressed {{
                background-color: rgba(255, 255, 255, 0.16);
            }}

            QPushButton#CloseBtn {{
                background: transparent;
                color: {SECONDARY_TEXT_COLOR};
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 700;
            }}
            QPushButton#CloseBtn:hover {{
                background-color: {ACCENT_COLOR};
                color: white;
            }}
            QPushButton#CloseBtn:pressed {{
                background-color: {ACCENT_HOVER};
            }}

            /* Scrollbars */
            QScrollBar:vertical {{
                background: transparent;
                width: 10px;
                margin: 2px 2px 2px 2px;
            }}
            QScrollBar::handle:vertical {{
                background: rgba(255, 255, 255, 0.18);
                min-height: 30px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: rgba(255, 255, 255, 0.28);
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: transparent;
                height: 10px;
                margin: 2px;
            }}
            QScrollBar::handle:horizontal {{
                background: rgba(255, 255, 255, 0.18);
                min-width: 30px;
                border-radius: 5px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: rgba(255, 255, 255, 0.28);
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0px;
                background: transparent;
            }}

            /* Tooltips */
            QToolTip {{
                background: rgba(0,0,0,0.85);
                color: #FFF;
                border: 1px solid rgba(255,255,255,0.10);
                padding: 6px 8px;
                border-radius: 6px;
                font-size: 12px;
            }}
        """)


class ImageLoaderWorker(QThread):
    imageLoaded = pyqtSignal(int, bytes, str, bytes, str)

    def __init__(self, items, timeout: float = 5.0, max_attempts: int = 2):
        super().__init__()
        self.items = items
        self.timeout = timeout
        self.max_attempts = max(1, max_attempts)

    def _log(self, message: str) -> None:
        logger_instance = globals().get("logger")
        if logger_instance is None:
            return
        try:
            logger_instance.log(2, message)
        except Exception:
            pass

    def _fetch_image_bytes(self, url: Optional[str]) -> Optional[bytes]:
        if not url:
            return None
        last_error = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.ok and response.content:
                    return response.content
                last_error = RuntimeError(f"status={response.status_code}")
            except requests.RequestException as exc:
                last_error = exc
            if last_error:
                self._log(f"Attempt {attempt} fetching {url} failed: {last_error}")
        return None

    def run(self):
        for idx, item in enumerate(self.items):
            skin_bytes = self._fetch_image_bytes(item.get('image'))
            if skin_bytes is None:
                fallback_skin = safe_load_pixmap(
                    None,
                    size=(120, 120),
                    placeholder_text="IMAGE\nUNAVAILABLE",
                    background="#2C2C2C",
                    text_color=ACCENT_COLOR
                )
                skin_bytes = pixmap_to_bytes(fallback_skin)

            rarity_info = item.get('rarity', {}) or {}
            rarity_bytes = self._fetch_image_bytes(rarity_info.get('icon'))
            if rarity_bytes is None:
                fallback_rarity = safe_load_pixmap(
                    None,
                    size=(24, 24),
                    placeholder_text="?",
                    background="#2C2C2C",
                    text_color=ACCENT_COLOR
                )
                rarity_bytes = pixmap_to_bytes(fallback_rarity)

            self.imageLoaded.emit(
                idx,
                skin_bytes,
                item.get('name', 'Unknown Item'),
                rarity_bytes,
                rarity_info.get('name', 'Unknown')
            )


class ShopLoaderWorker(QObject):
    finished = pyqtSignal(list, dict)
    def __init__(self, auth, logger):
        super().__init__()
        self.auth = auth
        self.logger = logger
    def run(self):
        riot_shop = Riot.Shop(self.auth, self.logger)
        shop_items = riot_shop.get_daily_shop()
        currency = riot_shop.get_currency()
        self.finished.emit(shop_items, currency)


def init_game_loader(headers, logger, puuid, port, encoded_pass, auth):
    global ingame_loader
    from Loader import Loader

    ingame_loader = Loader(
        headers=headers,
        logger=logger,
        puuid=puuid,
        port=port,
        encoded_pass=encoded_pass,
        auth=auth
    )


# --- Finish Loading Function ---
def finish_loading():
    global loading_screen, main_window, auth, timer
    # Create and show the main window passing the authenticated account details.
    main_window = MainWindow(account_name=f"{auth.account_name}#{auth.account_tag}")

    timer = QTimer()
    timer.timeout.connect(start_game_check)
    timer.start(500)

    print(f"Login complete. Welcome, {auth.account_name}#{auth.account_tag}!")
    loading_screen.setVisible(False)
    main_window.setVisible(True)
    return True

class ProgressCircle(QFrame):
    def __init__(self, icon_size, badge_padding=3, progress=0, parent=None):
        super().__init__(parent)
        self.icon_size = icon_size
        self.badge_padding = badge_padding
        self.progress = progress  # progress from 0 to 100
        # The total size covers the icon plus padding for the progress circle.
        size = icon_size + 2 * badge_padding
        self.setFixedSize(size, size)
        self.setStyleSheet("background: transparent;")

    def setProgress(self, p: float):
        self._progress = p
        self.update()

    def getProgress(self):
        return self._progress

    def paintEvent(self, a0):
        super().paintEvent(a0)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        # Define the rectangle where the arc will be drawn.
        pen_width = 3  # thickness of progress circle
        rect = self.rect().adjusted(pen_width, pen_width, -pen_width, -pen_width)

        # Draw the background ring (full circle in grey)
        pen = QPen(QColor(50, 50, 50))
        pen.setWidth(pen_width)
        painter.setPen(pen)
        painter.drawEllipse(rect)

        # Draw the progress arc
        pen.setColor(QColor(42, 209, 149))
        painter.setPen(pen)
        # Calculate span angle in terms of 1/16 degrees.
        span_angle = int((int(self.getProgress()) / 100.0) * 360 * 16)
        # Starting angle: 90 degrees (so that the arc begins at the top)
        start_angle = 90 * 16
        painter.drawArc(rect, start_angle, span_angle)

    progress = pyqtProperty(float, fget=getProgress, fset=setProgress)


def create_player_card(level, name, title, rank_icon_path,
                        background_img_bytes, progress_value,
                        is_user: bool = True, is_leader: bool = False):
    # === ENHANCED CONSTANTS ===
    CARD_W, CARD_H = 240, 480
    RANK_ICON_SIZE = 64  # visible part
    PROGRESS_DIAMETER = RANK_ICON_SIZE + 20  # outer circle
    NAME_TAG_HEIGHT = 52

    # ────── Enhanced card shell ──────
    card = QFrame()
    card.setObjectName("playerCard")
    card.setFixedSize(CARD_W, CARD_H)

    # Enhanced styling with modern gradients and better visual hierarchy
    user_gradient = "qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, stop: 0 rgba(255, 70, 85, 0.15), stop: 0.3 rgba(255, 70, 85, 0.08), stop: 1 rgba(26, 26, 26, 0.95))"
    normal_gradient = "qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, stop: 0 rgba(255, 255, 255, 0.06), stop: 0.3 rgba(255, 255, 255, 0.03), stop: 1 rgba(18, 18, 18, 0.95))"

    card.setStyleSheet(f"""
            QFrame#playerCard {{
                border-radius: 24px;
                background: {user_gradient if is_user else normal_gradient};
                border: 1px solid {BORDER_COLOR};
            }}
            QFrame#playerCard:hover {{
                background: {user_gradient.replace('0.95)', '0.98)') if is_user else normal_gradient.replace('0.95)', '0.98)')};
                border-color: {BORDER_HIGHLIGHT};
                
                
            }}
        """)

    # Enhanced glow around entire card
    glow = QGraphicsDropShadowEffect()
    glow.setBlurRadius(50)
    glow.setXOffset(0)
    glow.setYOffset(12)
    glow.setColor(QColor(0, 0, 0, 120))
    card.setGraphicsEffect(glow)

    # ────── blurred background image ──────
    bg = QLabel(card)
    pm = QPixmap()
    pm.loadFromData(background_img_bytes)
    if not pm.isNull():
        pm = pm.scaled(CARD_W, CARD_H, Qt.KeepAspectRatioByExpanding,
                       Qt.SmoothTransformation)
        bg.setPixmap(pm)
        blur = QGraphicsBlurEffect()
        blur.setBlurRadius(2)
        bg.setGraphicsEffect(blur)
    bg.setGeometry(0, 0, CARD_W, CARD_H)
    bg.lower()

    # dark gradient overlay (helps text contrast)
    ov = QLabel(card)
    ov.setGeometry(0, 0, CARD_W, CARD_H)
    ov.setStyleSheet("""
            background:qlineargradient(
               x1:0,y1:0,x2:0,y2:1,
               stop:0 rgba(0,0,0,0.1),
               stop:0.4 rgba(0,0,0,0.3),
               stop:0.7 rgba(0,0,0,0.8),
               stop:1 rgba(0,0,0,0.92));
            border-radius:16px;
        """);
    ov.lower()

    # ────── main vertical layout ──────
    root = QVBoxLayout(card)
    root.setContentsMargins(14, 14, 14, 14)
    root.setSpacing(10)

    # ── Enhanced level badge (top) ──
    lvl_frame = QFrame()
    lvl_frame.setObjectName("levelBadge")
    lvl_frame.setFixedHeight(36)  # Enhanced height for better visual presence
    lvl_frame.setStyleSheet(f"""
        QFrame#levelBadge {{
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(0,0,0,0.8),
                stop:0.5 rgba(0,0,0,0.7),
                stop:1 rgba(0,0,0,0.6)
            );
            border: 1px solid rgba(255,255,255,0.25);
            border-radius: 18px;
            
        }}
    """)

    lvl_lay = QHBoxLayout(lvl_frame)
    lvl_lay.setContentsMargins(16, 0, 16, 0)
    lvl_lay.setSpacing(8)

    # Enhanced star container with better gradient
    star_container = QFrame()
    star_container.setFixedSize(24, 24)
    star_container.setStyleSheet(f"""
        background: qradialgradient(
            cx:0.5, cy:0.5, radius:0.9,
            fx:0.5, fy:0.5,
            stop:0 {ACCENT_COLOR},
            stop:0.7 {ACCENT_HOVER},
            stop:1 rgba(255, 70, 85, 0.3)
        );
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.2);
    """)
    star_layout = QHBoxLayout(star_container)
    star_layout.setContentsMargins(0, 0, 0, 0)

    star = QLabel("★")
    star.setStyleSheet(f"""
        color: white;
        font-size: 16px;
        background: transparent;
        font-weight: 700;
        
    """)
    star.setAlignment(Qt.AlignCenter)
    star_layout.addWidget(star)

    # Enhanced level number with better typography
    lvl_num = QLabel(str(level))
    lvl_num.setStyleSheet(f"""
        color: {PRIMARY_TEXT_COLOR};
        font-size: 16px;
        font-weight: 700;
        background: transparent;
        
        letter-spacing: 0.5px;
    """)

    lvl_lay.addWidget(star_container)
    lvl_lay.addWidget(lvl_num)
    root.addWidget(lvl_frame, alignment=Qt.AlignHCenter)

    # leave some breathing room
    root.addStretch(1)

    # ── Enhanced title box ──
    title_box = QFrame()
    title_box.setStyleSheet(f"""
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                stop: 0 rgba(15,18,24,0.9),
                stop: 1 rgba(20,23,29,0.85));
            padding: 8px 16px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        """)
    tlay = QVBoxLayout(title_box)
    tlay.setContentsMargins(0, 0, 0, 0)
    title_lbl = QLabel(title)
    title_lbl.setFont(QFont(FONT_FAMILY, 13))
    title_lbl.setStyleSheet(f"""
        color: {SECONDARY_TEXT_COLOR};
        font-style: italic;
        text-align: center;
        
    """)
    title_lbl.setAlignment(Qt.AlignCenter)
    tlay.addWidget(title_lbl)
    root.addWidget(title_box, alignment=Qt.AlignHCenter)

    # ────── bottom stack (progress badge + name) ──────
    bottom = QFrame()
    blay = QVBoxLayout(bottom)
    blay.setContentsMargins(0, 0, 0, 0)
    blay.setSpacing(-PROGRESS_DIAMETER // 3)  # negative -> overlap upward

    # progress / rank badge
    badge = ProgressCircle(RANK_ICON_SIZE, badge_padding=5, parent=bottom)
    blay.addWidget(badge, alignment=Qt.AlignHCenter)
    badge.setProgress(progress_value)
    badge.setFixedSize(PROGRESS_DIAMETER, PROGRESS_DIAMETER)
    badge.setStyleSheet(f"""
        border-radius:{PROGRESS_DIAMETER // 2}px;
        background:rgba(15,18,24,0.85);
    """)
    rank_pixmap = safe_load_pixmap(
        rank_icon_path,
        size=(RANK_ICON_SIZE, RANK_ICON_SIZE),
        placeholder_text="?"
    )

    icon_lbl = QLabel()
    icon_lbl.setPixmap(rank_pixmap)
    icon_lbl.setAlignment(Qt.AlignCenter)
    icon_lbl.setFixedSize(RANK_ICON_SIZE, RANK_ICON_SIZE)
    icon_lbl.setStyleSheet("background:transparent;")

    badge_lay = QHBoxLayout(badge)
    badge_lay.setContentsMargins(badge.badge_padding,  # left
                                 badge.badge_padding,  # top
                                 badge.badge_padding,  # right
                                 badge.badge_padding)  # bottom
    badge_lay.addWidget(icon_lbl, alignment=Qt.AlignCenter)

    # Enhanced name bar
    name_bar = QFrame()
    name_bar.setFixedHeight(NAME_TAG_HEIGHT)
    name_bar.setStyleSheet(f"""
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                stop: 0 rgba(15,18,24,0.9),
                stop: 1 rgba(20,23,29,0.85));
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.15);
        """)
    nlay = QHBoxLayout(name_bar)
    nlay.setContentsMargins(16, 0, 16, 0)
    name_lbl = QLabel(name)
    name_lbl.setFont(QFont(FONT_FAMILY, 12, QFont.Bold))
    name_lbl.setStyleSheet(f"""
        color: {PRIMARY_TEXT_COLOR};
        letter-spacing: 0.5px;
        
        font-weight: 700;
    """)
    name_lbl.setAlignment(Qt.AlignCenter)
    nlay.addWidget(name_lbl, alignment=Qt.AlignCenter)
    blay.addWidget(name_bar, alignment=Qt.AlignHCenter)

    root.addWidget(bottom, alignment=Qt.AlignBottom)

    return card


def create_player_bar(player_data: dict, min_width: int, is_host: bool = False) -> QFrame:
    # Enhanced color scheme
    BAR_BG = "#161820"  # Darker, more sophisticated background
    BAR_RADIUS = 12  # Slightly increased radius
    BAR_HEIGHT = 75  # Slightly taller
    BAR_PADDING = 14
    STATE_STRIPE_W = 6
    AGENT_SIZE = 48  # Slightly larger agent icon
    RANK_SIZE = 50  # Slightly larger rank icon

    COLOR_TEXT = "#F0F0F0"  # Brighter text for better contrast
    COLOR_DETAIL = "#B8B8B8"  # Slightly brighter details
    COLOR_HOST = "#FFD700"
    COLOR_ACCENT = "#5D8FEF"  # Slightly adjusted accent color
    COLOR_AGENT_BG = "#242630"  # Darker agent background
    COLOR_RANK_BG = "#1A1C24"  # Darker rank background

    BORDER_COLOR = "#2A2D38"
    HOVER_BG = "#1E2028"
    PEEK_STATS_COLOR = "#4CAF50"
    ALERT_COLOR = "#F44336"

    STATE_COLORS = {
        "": "transparent",
        "selected": COLOR_ACCENT,
        "locked": "#8BC34A",
    }

    # Rank-specific background colours
    RANK_BG_COLORS = {
        "unranked": "#444444",
        "iron": "#8294a0",
        "silver": "#ececec",
        "gold": "#eeb74c",
        "plat": "#4c96ee",
        "diamond": "#caa0f2",
        "ascendant": "#7ed872",
        "immortal": "#b95a5a",
        "radiant": "#337f78",
    }
    tier = int(player_data.get("tier", 0))
    rank_name: str = Utils(auth.logger).get_rank_name_from_tier(tier, True)
    rank_color = RANK_BG_COLORS.get(rank_name.lower(), "#444444")

    # Select state stripe color
    state = player_data.get("agent_state", "")
    stripe_color = STATE_COLORS.get(state, STATE_COLORS[""])

    # Main container
    bar = QFrame()
    bar.setObjectName("playerBar")
    bar.setFixedHeight(BAR_HEIGHT)
    bar.setMinimumWidth(min_width)

    # Drop shadow for depth
    shadow = QGraphicsDropShadowEffect(bar)
    shadow.setBlurRadius(12)
    shadow.setOffset(0, 2)
    shadow.setColor(QColor(0, 0, 0, 100))
    bar.setGraphicsEffect(shadow)

    # Layout
    layout = QHBoxLayout(bar)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)

    # 1) State stripe
    stripe = QFrame(bar)
    stripe.setObjectName("stateStripe")
    stripe.setFixedWidth(STATE_STRIPE_W)
    layout.addWidget(stripe)

    # 2) Agent icon
    agent = QLabel(bar)
    agent.setObjectName("agentIcon")
    agent.setFixedSize(AGENT_SIZE, AGENT_SIZE)
    agent.setAlignment(Qt.AlignCenter)
    if player_data.get("agent_icon"):
        pix = QPixmap()
        pix.loadFromData(player_data["agent_icon"])
        if not pix.isNull():
            scaled = pix.scaled(AGENT_SIZE - 8, AGENT_SIZE - 8, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            agent.setPixmap(scaled)
    layout.addSpacing(BAR_PADDING)
    layout.addWidget(agent)

    # 3) Name and details container
    info = QVBoxLayout()
    info.setContentsMargins(0, 0, 0, 0)
    info.setSpacing(4)
    # Name label with larger, bolder font
    name = QLabel(player_data.get("name", "Unknown"), bar)
    name.setObjectName("nameLabel")
    name.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    name.setStyleSheet("font: bold 20px 'Segoe UI';")
    info.addWidget(name)

    # Details enclosed in a padded widget with semi-transparent background
    details_widget = QWidget(bar)
    details_widget.setStyleSheet("""
            background: rgba(0, 0, 0, 0.25);
            border-radius: 5px;
            padding: 4px 8px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        """)
    details = QHBoxLayout(details_widget)
    details.setContentsMargins(8, 4, 8, 4)
    details.setSpacing(16)

    level_container = QWidget()
    level_layout = QHBoxLayout(level_container)
    level_layout.setContentsMargins(0, 0, 0, 0)
    level_layout.setSpacing(4)

    level_icon = QLabel("👑")  # Using emoji as placeholder, replace with proper icon
    level_icon.setStyleSheet("font-size: 12px;")
    level_layout.addWidget(level_icon)

    lvl = int(player_data.get("level", 0))
    lbl_level = QLabel(f"{lvl if lvl > 0 else '?'}")
    lbl_level.setObjectName("detailLabel")
    level_layout.addWidget(lbl_level)
    details.addWidget(level_container)

    kd_container = QWidget()
    kd_layout = QHBoxLayout(kd_container)
    kd_layout.setContentsMargins(0, 0, 0, 0)
    kd_layout.setSpacing(4)
    kd_icon = QLabel("🎯")  # Using emoji as placeholder
    kd_icon.setStyleSheet("font-size: 12px;")
    kd_layout.addWidget(kd_icon)
    kd_value = player_data.get('kd')
    if kd_value is None:
        kd_value = 0.0
    kd_color = (PEEK_STATS_COLOR if kd_value >= 1.0 else ALERT_COLOR if kd_value < 0.7 else COLOR_DETAIL) if isinstance(kd_value, (int, float)) else COLOR_DETAIL
    lbl_kd = QLabel(f"{kd_value}")
    lbl_kd.setStyleSheet(f"color: {kd_color}; font: 14px 'Segoe UI';")
    kd_layout.addWidget(lbl_kd)
    details.addWidget(kd_container)

    # Headshot % with conditional coloring
    hs_container = QWidget()
    hs_layout = QHBoxLayout(hs_container)
    hs_layout.setContentsMargins(0, 0, 0, 0)
    hs_layout.setSpacing(4)
    hs_icon = QLabel("🎯")  # Using emoji as a placeholder
    hs_icon.setStyleSheet("font-size: 12px;")
    hs_layout.addWidget(hs_icon)
    hs_value = player_data.get('hs')
    if hs_value is None:
        hs_value = 0.0
    hs_color = PEEK_STATS_COLOR if hs_value >= 25.0 else ALERT_COLOR if hs_value < 15.0 else COLOR_DETAIL
    lbl_hs = QLabel(f"{hs_value:.1f}%")
    lbl_hs.setStyleSheet(f"color: {hs_color}; font: 14px 'Segoe UI';")
    hs_layout.addWidget(lbl_hs)
    details.addWidget(hs_container)
    mh = player_data.get("match_history", [])
    if isinstance(mh, list) and mh:
        wins = mh.count(True)
        losses = len(mh) - wins
        rate = wins / len(mh) * 100

        # Calculate streak
        current_streak = 0
        streak_type = None
        for result in mh:
            if streak_type is None:
                streak_type = result
                current_streak = 1
            elif result == streak_type:
                current_streak += 1
            else:
                break

        streak_color = PEEK_STATS_COLOR if streak_type and current_streak >= 3 else \
            ALERT_COLOR if not streak_type and current_streak >= 3 else COLOR_DETAIL

        streak_text = f"{'W' if streak_type else 'L'}{current_streak}" if current_streak >= 3 else ""
        wl_text = f"{wins}-{losses} ({rate:.0f}%)"
        if streak_text:
            wl_text += f" [{streak_text}]"
    else:
        wl_text = "N/A"
        streak_color = COLOR_DETAIL

    wl_container = QWidget()
    wl_layout = QHBoxLayout(wl_container)
    wl_layout.setContentsMargins(0, 0, 0, 0)
    wl_layout.setSpacing(4)
    wl_icon = QLabel("📊")  # Using emoji as a placeholder
    wl_icon.setStyleSheet("font-size: 12px;")
    wl_layout.addWidget(wl_icon)
    lbl_wl = QLabel(wl_text)
    lbl_wl.setStyleSheet(f"color: {streak_color}; font: 14px 'Segoe UI';")
    wl_layout.addWidget(lbl_wl)
    details.addWidget(wl_container)

    details.addStretch()
    info.addWidget(details_widget)
    layout.addSpacing(BAR_PADDING)
    layout.addLayout(info)

    bar.setStyleSheet(bar.styleSheet() + f"""
        QFrame#playerBar:hover {{
            background: qlineargradient(
                x1: 1, y1: 1, x2: 0, y2: 0,
                stop: 0 {HOVER_BG},
                stop: 0.20 {rank_color},
                stop: 0.21 {HOVER_BG},
                stop: 1 {HOVER_BG}
            );
            border: 1px solid {BORDER_COLOR};
        }}
        """)

    # 4) Rank icon
    layout.addStretch()
    rank = QLabel(bar)
    rank.setObjectName("rankIcon")
    rank.setFixedSize(RANK_SIZE, RANK_SIZE)
    rank.setAlignment(Qt.AlignCenter)
    rank_icon_path = f"assets/rank/smallicon_{tier}.png"
    rank_pixmap = safe_load_pixmap(
        rank_icon_path,
        size=(RANK_SIZE - 6, RANK_SIZE - 6),
        placeholder_text="?"
    )
    rank.setPixmap(rank_pixmap)
    layout.addWidget(rank)
    layout.addSpacing(BAR_PADDING)

    # Unified QSS styling with a diagonal gradient background using the rank color
    bar.setStyleSheet(f"""
    QFrame#playerBar {{
      border-radius: {BAR_RADIUS}px;
      background: qlineargradient(
          x1: 1, y1: 1, x2: 0, y2: 0,
          stop: 0 {BAR_BG},
          stop: 0.20 {rank_color},
          stop: 0.21 {BAR_BG},
          stop: 1 {BAR_BG}
      );
    }}
    QFrame#stateStripe {{
      background: {stripe_color};
      border-top-left-radius: {BAR_RADIUS}px;
      border-bottom-left-radius: {BAR_RADIUS}px;
    }}
    QLabel {{
        color: {COLOR_TEXT};
        background: transparent;
    }}
    QLabel#agentIcon {{
      background: {COLOR_AGENT_BG};
      border-radius: {AGENT_SIZE // 2}px;
    }}
    QLabel#detailLabel {{
      color: {COLOR_DETAIL};
      font: 14px "Segoe UI";
    }}
    QLabel#rankIcon {{
      background: {COLOR_RANK_BG};
      border-radius: {RANK_SIZE // 2}px;
    }}
    """.replace("{HOST}", COLOR_HOST).replace("{TEXT}", COLOR_TEXT)
    )

    return bar

def update_game_status(result: dict):
    while loader_layout.count():
        child = loader_layout.takeAt(0)
        if child.widget():
            child.widget().deleteLater()

    # Check if state id is 0 (Offline condition)
    if result["state"]["id"] == 0:
        loader_layout.setDirection(QBoxLayout.LeftToRight)

        offline_label = QLabel("You are currently offline.")
        offline_label.setAlignment(Qt.AlignCenter)  # Center the label
        offline_label.setStyleSheet(f"""
            {TEXT_FONT}
            padding: 20px 30px;
            background: {GLASS_BACKGROUND};
            border: {GLASS_BORDER};
            border-radius: 10px;
        """)
        loader_layout.addWidget(offline_label)
        info_queue_label = info_container.findChild(QLabel, "info_queue_label")
        if info_queue_label is not None:
            info_queue_label.setText("Offline.")

    elif result["state"]["id"] == 1:
        loader_layout.setDirection(QBoxLayout.LeftToRight)

        members_data = result["party"]["Members"]
        player_cards = []
        for member_data in members_data:
            level: str = str(member_data["PlayerIdentity"]["AccountLevel"]) if not member_data["PlayerIdentity"]["HideAccountLevel"] else "--"
            name: str = member_data["PlayerIdentity"]["AccountName"]
            title: str = member_data["PlayerIdentity"]["PlayerTitle"]
            is_user: bool = member_data["is_user"]

            rank = member_data["Rank"]
            rr = member_data["RR"]
            tier = member_data["Tier"]
            rank_icon_path = f"assets/rank/smallicon_{tier}.png"

            background_bytes = member_data["PlayerIdentity"]["RawPlayerCard"]

            player_card = create_player_card(level, name, title, rank_icon_path, background_bytes, progress_value=rr, is_user=is_user, is_leader=member_data.get("IsOwner", False))
            player_cards.append(player_card)

            loader_layout.addWidget(player_card, alignment=Qt.AlignCenter)

            info_queue_label = info_container.findChild(QLabel, "info_queue_label")
            if info_queue_label is not None:
                info_queue_label.setText(f"Mode: {result['party']['mode']}")

    elif result["state"]["id"] == 2:
        loader_layout.setDirection(QBoxLayout.LeftToRight)

        members_data = result["party"]["Members"]
        player_cards = []
        for member_data in members_data:
            level: str = str(member_data["PlayerIdentity"]["AccountLevel"]) if not member_data["PlayerIdentity"]["HideAccountLevel"] else "HIDDEN"
            name: str = member_data["PlayerIdentity"]["AccountName"]
            title: str = member_data["PlayerIdentity"]["PlayerTitle"]
            is_user: bool = member_data["is_user"]

            rank = member_data["Rank"]
            rr = member_data["RR"]
            tier = member_data["Tier"]
            rank_icon_path = f"assets/rank/smallicon_{tier}.png"

            background_bytes = member_data["PlayerIdentity"]["RawPlayerCard"]

            player_card = create_player_card(level, name, title, rank_icon_path, background_bytes, progress_value=rr, is_user=is_user, is_leader=member_data.get("IsOwner", False))
            player_cards.append(player_card)

            loader_layout.addWidget(player_card, alignment=Qt.AlignCenter)

            info_queue_label = info_container.findChild(QLabel, "info_queue_label")
            if info_queue_label is not None:
                info_queue_label.setText(f"QUEUEING | Mode: {result['party']['mode']}")

    elif result["state"]["id"] == 3:
        loader_layout.setDirection(QBoxLayout.LeftToRight)

        try:
            data = result["data"]
            players = data["players"]
        except TypeError:
            return

        gamemode_name = str(data["gamemode"]).capitalize()
        map_name = str(data["map"]).capitalize()

        info_queue_label = info_container.findChild(QLabel, "info_queue_label")
        if info_queue_label is not None:
            info_queue_label.setText(f"AGENT SELECT: {map_name} | {gamemode_name}")

        # Determine the user's team to correctly separate allies from enemies
        user_team = ""
        for p in players:
            if p.get("is_user"):
                user_team = p.get("team", "").lower()
                break

        # Create dedicated widgets for ally and enemy teams
        ally_team_widget = QWidget()
        ally_team_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        ally_layout = QVBoxLayout(ally_team_widget)
        ally_layout.setAlignment(Qt.AlignTop)
        ally_layout.setSpacing(10)

        # Add titles for each team for clarity
        ally_title = QLabel("Your Team")
        ally_title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {PRIMARY_TEXT_COLOR}; padding-bottom: 5px;")
        ally_layout.addWidget(ally_title, alignment=Qt.AlignCenter)

        for player in players:
            player_bar = create_player_bar(player, 400, player.get("is_user", False))
            if player.get("team", "").lower() == user_team:
                ally_layout.addWidget(player_bar)

        ally_layout.addStretch(stretch=1)
        ally_layout.setContentsMargins(0, 15, 0, 15)

        loader_layout.addWidget(ally_team_widget)


    elif result["state"]["id"] == 4:
        loader_layout.setDirection(QBoxLayout.LeftToRight)

        loader_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        try:
            data = result["data"]
            players = data["players"]
        except TypeError:
            return
        gamemode_name = str(data["gamemode"]).capitalize()
        map_name = str(data["map"]).capitalize()

        info_queue_label = info_container.findChild(QLabel, "info_queue_label")
        if info_queue_label is not None:
            info_queue_label.setText(f"IN-GAME: {map_name} | {gamemode_name}")

        blue_team_widget = QWidget()
        blue_team_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        blue_layout = QVBoxLayout(blue_team_widget)
        blue_layout.setAlignment(Qt.AlignTop)
        blue_layout.setSpacing(25)

        red_team_widget = QWidget()
        red_team_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        red_layout = QVBoxLayout(red_team_widget)
        red_layout.setAlignment(Qt.AlignTop)
        red_layout.setSpacing(25)

        for player in players:
            player_bar = create_player_bar(player, 400, player.get("is_user", False))
            if player.get("team").lower() == "blue":
                blue_layout.addWidget(player_bar)
            elif player.get("team").lower() == "red":
                red_layout.addWidget(player_bar)

        blue_layout.addStretch(stretch=1)
        blue_layout.setContentsMargins(0, 15, 0, 15)
        red_layout.addStretch(stretch=1)
        red_layout.setContentsMargins(0, 15, 0, 15)

        loader_layout.addWidget(blue_team_widget)

        # Add a visual separator between the teams
        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        separator.setStyleSheet(f"color: {SECONDARY_UI_COLOR};")
        loader_layout.addWidget(separator)

        loader_layout.addWidget(red_team_widget)

    loader_container.update()


# Result will have alot of data. Update the gui based on that data.
# result = dict{"state": dict{"id": int, "text": str}}
# state id can be 0 or 1. 0 being offline (valorant is not open), 1 being online (In menu), 1 will return the party dict in the result dict.
# party_obj - dict{"state": dict{"id": int, "text": str}, "party": dict{"id": str, "Members": list[dict{"Subject": str, "CompetitiveTier": int, "PlayerIdentity": dict{"Subject": str, "PlayerCardID": str, "PlayerTitleID": str, "AccountLevel": int, "PreferredLevelBorderID": str, "Incognito": bool, "HideAccountLevel": bool}, "SeasonalBadgeInfo": None, "IsOwner": bool, "QueueEligibleRemainingAccountLevels": int, "Pings": list[dict{"Ping": int, "GamePodID": str}], "IsReady": bool, "IsModerator": bool, "UseBroadcastHUD": bool, "PlatformType": str, "PreferredAgentInfo": None, "Rank": str}], "state": str, "accessibility": str, "mode": str}}

class GameLoaderWorker(QThread):
    result_ready = pyqtSignal(object)  # Signal to emit when results are ready

    def run(self):
        result = ingame_loader.run()
        self.result_ready.emit(result)


def start_game_check():
    global worker
    # Don't start a new check if one is still running
    if worker is None or not worker.isRunning():
        worker = GameLoaderWorker()
        worker.result_ready.connect(update_game_status)
        worker.start()


if __name__ == '__main__':
    worker = None
    # Enable HiDPI scaling and crisp pixmaps for better rendering on modern displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    # Global typography
    from PyQt5.QtGui import QFont
    app_font = QFont()
    app_font.setFamily('Segoe UI')
    app_font.setPointSize(10)
    app.setFont(app_font)
    app.setStyleSheet(build_global_qss())
    app_icon_pixmap = safe_load_pixmap(
        "assets/Zoro.png",
        size=(256, 256),
        placeholder_text="Z",
        background=SECONDARY_UI_COLOR,
        text_color=PRIMARY_TEXT_COLOR
    )
    app.setWindowIcon(QIcon(app_icon_pixmap))

    logger = Logger("Zoro", "logs/Zoro", ".log")
    logger.load_public_key(key=KEY)

    auth = Riot.Auth(logger)

    # Show the loading screen.
    loading_screen = LoadingScreen(auth)
    loading_screen.main_window_ready.connect(finish_loading)
    loading_screen.setVisible(True)

    # Only run further initialization if logged in.
    if auth.log_in():
        init_game_loader(auth.headers, auth.logger, auth.puuid, auth.port, auth.encoded_pass, auth)
        finish_loading()
    else:
        loading_screen.set_message("Login Failed. Please make sure Riot Client is open and you're logged in.")

    sys.exit(app.exec_())
