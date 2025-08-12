# main.py
import sys
import json
import base64
import hashlib
import hmac
import urllib.parse
import uuid
import secrets
import re
import socket
import subprocess
from datetime import datetime
import os
import io
import colorsys

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QLineEdit, QComboBox, QGroupBox,
    QGridLayout, QFileDialog, QFrame, QSizePolicy, QColorDialog, QSpinBox, QCheckBox,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QByteArray
from PyQt6.QtGui import QFont, QPalette, QColor, QClipboard, QIcon, QPixmap, QImage

# Optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    import qrcode
    from PIL import Image
    HAS_QRCODE = True
except Exception:
    HAS_QRCODE = False


# Thread for pinging
class PingThread(QThread):
    result = pyqtSignal(str)

    def __init__(self, host: str):
        super().__init__()
        self.host = host

    def run(self):
        try:
            param = '-n' if sys.platform.startswith('win') else '-c'
            command = ['ping', param, '4', self.host]
            if sys.platform.startswith('win'):
                result = subprocess.run(command, capture_output=True, text=True, encoding="cp866", timeout=10)
            else:
                result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=10)
            output = result.stdout if result.stdout else result.stderr
            self.result.emit(output)
        except Exception as e:
            self.result.emit(f"Error: {str(e)}")


# Thread for generating QR in background (to avoid blocking UI)
class QRThread(QThread):
    finished = pyqtSignal(bytes)
    error = pyqtSignal(str)

    def __init__(self, data: str, box_size: int = 6, border: int = 2):
        super().__init__()
        self.data = data
        self.box_size = box_size
        self.border = border

    def run(self):
        try:
            if not HAS_QRCODE:
                self.error.emit("qrcode/Pillow not installed")
                return
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                               box_size=self.box_size, border=self.border)
            qr.add_data(self.data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            self.finished.emit(buf.getvalue())
        except Exception as e:
            self.error.emit(str(e))


# Simple Base58 implementation (no external deps)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(BASE58_ALPHABET[r])
    res = ''.join(reversed(res)) or '1'
    zeros = 0
    for ch in b:
        if ch == 0:
            zeros += 1
        else:
            break
    return '1' * zeros + res


def base58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + BASE58_ALPHABET.index(ch)
    full_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b''
    zeros = 0
    for ch in s:
        if ch == '1':
            zeros += 1
        else:
            break
    return b'\x00' * zeros + full_bytes


class DevUtilityPro(QMainWindow):
    def __init__(self):
        super().__init__()

        # Settings (to persist language)
        self.settings = QSettings("devtoolbox", "wDevToolbox")

        # Language management
        self.supported_langs = ["en", "ru"]
        saved_lang = self.settings.value("language", "en")
        self.current_lang = saved_lang if saved_lang in self.supported_langs else "en"

        # Translations dictionary (kept minimal for new controls)
        self.translations = {
            "title": {"en": "wDevToolbox", "ru": "wDevToolbox"},
            "ready": {"en": "Ready", "ru": "Готово"},
            "lang_en": {"en": "English", "ru": "English"},
            "lang_ru": {"en": "Русский", "ru": "Русский"},
            "tab_text": {"en": "Text", "ru": "Текст"},
            "tab_encoding": {"en": "Encoding", "ru": "Кодирование"},
            "tab_hashing": {"en": "Hashing", "ru": "Хеширование"},
            "tab_json": {"en": "JSON", "ru": "JSON"},
            "tab_time": {"en": "Time", "ru": "Время"},
            "tab_network": {"en": "Network", "ru": "Сеть"},
            "tab_generators": {"en": "Generators", "ru": "Генераторы"},
            "tab_colors": {"en": "Colors", "ru": "Цвета"},
            "group_input_text": {"en": "Input Text", "ru": "Входной текст"},
            "group_transforms": {"en": "Text Transformations", "ru": "Преобразования текста"},
            "group_result": {"en": "Result", "ru": "Результат"},
            "placeholder_text_input": {"en": "Enter text to transform...", "ru": "Введите текст для преобразования..."},
            "upper_case": {"en": "UPPER CASE", "ru": "ВЕРХНИЙ РЕГИСТР"},
            "lower_case": {"en": "lower case", "ru": "нижний регистр"},
            "swap_case": {"en": "Swap Case", "ru": "Сменить регистр"},
            "camel_case": {"en": "Camel Case", "ru": "CamelCase"},
            "snake_case": {"en": "snake_case", "ru": "snake_case"},
            "remove_spaces": {"en": "Remove Spaces", "ru": "Удалить пробелы"},
            "trim_whitespace": {"en": "Trim Whitespace", "ru": "Обрезать пробелы"},
            "reverse_text": {"en": "Reverse Text", "ru": "Перевернуть текст"},
            "wrap_quotes": {"en": "Wrap Quotes", "ru": "В кавычки"},
            "count_chars": {"en": "Count Chars", "ru": "Подсчитать символы"},
            "clear": {"en": "Clear", "ru": "Очистить"},
            "regex_pattern": {"en": "Regex pattern", "ru": "RegEx шаблон"},
            "regex_replacement": {"en": "Replacement", "ru": "Замена"},
            "regex_flags": {"en": "Flags", "ru": "Флаги"},
            "regex_apply": {"en": "Apply RegEx Replace", "ru": "Применить RegEx"},
            "group_encoding_type": {"en": "Encoding Type", "ru": "Тип кодирования"},
            "group_encoding_input": {"en": "Input Data", "ru": "Данные"},
            "btn_encode": {"en": "Encode", "ru": "Кодировать"},
            "btn_decode": {"en": "Decode", "ru": "Декодировать"},
            "placeholder_encoding_input": {"en": "Enter text to encode/decode...", "ru": "Введите текст для кодирования/декодирования..."},
            "enc_Base64": {"en": "Base64", "ru": "Base64"},
            "enc_URL": {"en": "URL", "ru": "URL"},
            "enc_Base32": {"en": "Base32", "ru": "Base32"},
            "enc_ASCII": {"en": "ASCII", "ru": "ASCII"},
            "enc_Hex": {"en": "Hex", "ru": "Hex"},
            "enc_Base85": {"en": "Base85", "ru": "Base85"},
            "enc_Base58": {"en": "Base58", "ru": "Base58"},
            "group_hash_algorithm": {"en": "Hash Algorithm", "ru": "Алгоритм хеширования"},
            "group_hash_input": {"en": "Input Data", "ru": "Данные"},
            "btn_generate_hash": {"en": "Generate Hash", "ru": "Сгенерировать хеш"},
            "placeholder_hash_input": {"en": "Enter text to hash...", "ru": "Введите текст для хеширования..."},
            "hmac_key": {"en": "HMAC key (optional)", "ru": "Ключ HMAC (опционально)"},
            "hash_MD5": {"en": "MD5", "ru": "MD5"},
            "hash_SHA1": {"en": "SHA-1", "ru": "SHA-1"},
            "hash_SHA256": {"en": "SHA-256", "ru": "SHA-256"},
            "hash_SHA512": {"en": "SHA-512", "ru": "SHA-512"},
            "hash_BLAKE2b": {"en": "BLAKE2b", "ru": "BLAKE2b"},
            "hash_BLAKE2s": {"en": "BLAKE2s", "ru": "BLAKE2s"},
            "group_json_input": {"en": "JSON Input", "ru": "Ввод JSON"},
            "btn_format_json": {"en": "Format JSON", "ru": "Форматировать JSON"},
            "btn_minify_json": {"en": "Minify JSON", "ru": "Минифицировать JSON"},
            "btn_validate_json": {"en": "Validate JSON", "ru": "Проверить JSON"},
            "placeholder_json_input": {"en": "Enter JSON here...", "ru": "Вставьте JSON..."},
            "json_valid": {"en": "✅ Valid JSON", "ru": "✅ Валидный JSON"},
            "group_timestamp_converter": {"en": "Timestamp Converter", "ru": "Конвертер метки времени"},
            "label_timestamp": {"en": "Timestamp:", "ru": "Тimestamp:"},
            "label_datetime": {"en": "Date/Time:", "ru": "Дата/Время:"},
            "btn_to_date": {"en": "→ Convert to Date", "ru": "→ В дату"},
            "btn_to_timestamp": {"en": "→ Convert to Timestamp", "ru": "→ В timestamp"},
            "placeholder_timestamp": {"en": "Unix timestamp", "ru": "Unix timestamp"},
            "placeholder_datetime": {"en": "YYYY-MM-DD HH:MM:SS", "ru": "ГГГГ-MM-ДД ЧЧ:ММ:СС"},
            "btn_generate_unix": {"en": "Generate Unix Timestamp", "ru": "Сгенерировать Unix timestamp"},
            "btn_generate_iso": {"en": "Generate ISO Format", "ru": "Сгенерировать ISO"},
            "btn_copy_time": {"en": "Copy Result", "ru": "Скопировать"},
            "date_diff": {"en": "Date Difference", "ru": "Разница дат"},
            "btn_calc_diff": {"en": "Calc Difference", "ru": "Посчитать разницу"},
            "group_ip_lookup": {"en": "IP Lookup", "ru": "Поиск IP"},
            "label_hostname": {"en": "Hostname:", "ru": "Хост:"},
            "btn_lookup_ip": {"en": "Lookup IP", "ru": "Найти IP"},
            "label_ip_address": {"en": "IP Address:", "ru": "IP адрес:"},
            "group_ping_tool": {"en": "Ping Tool", "ru": "Ping"},
            "label_ping_host": {"en": "Host to ping:", "ru": "Хост для ping:"},
            "btn_ping": {"en": "Ping", "ru": "Ping"},
            "http_url": {"en": "URL:", "ru": "URL:"},
            "http_method": {"en": "Method:", "ru": "Метод:"},
            "http_send": {"en": "Send HTTP", "ru": "Отправить HTTP"},
            "http_result": {"en": "HTTP Result:", "ru": "HTTP Результат:"},
            "http_requires_requests": {"en": "HTTP client requires 'requests' package", "ru": "HTTP требует пакет 'requests'"},
            "group_password_generator": {"en": "Password Generator", "ru": "Генератор паролей"},
            "label_length": {"en": "Length:", "ru": "Длина:"},
            "label_include": {"en": "Include:", "ru": "Включить:"},
            "opt_uppercase": {"en": "Uppercase", "ru": "Заглавные"},
            "opt_no_uppercase": {"en": "No Uppercase", "ru": "Без заглавных"},
            "opt_digits": {"en": "Digits", "ru": "Цифры"},
            "opt_no_digits": {"en": "No Digits", "ru": "Без цифр"},
            "opt_symbols": {"en": "Symbols", "ru": "Символы"},
            "opt_no_symbols": {"en": "No Symbols", "ru": "Без символов"},
            "btn_generate_password": {"en": "Generate Password", "ru": "Сгенерировать пароль"},
            "group_uuid_generator": {"en": "UUID Generator", "ru": "Генератор UUID"},
            "btn_generate_uuid": {"en": "Generate UUID v4", "ru": "Сгенерировать UUID v4"},
            "qr_input": {"en": "Text / URL for QR", "ru": "Текст / URL для QR"},
            "btn_generate_qr": {"en": "Generate QR", "ru": "Сгенерировать QR"},
            "qr_requires": {"en": "QR requires 'qrcode' and 'Pillow' packages", "ru": "QR требует 'qrcode' и 'Pillow'"},
            "save_qr_png": {"en": "Save QR as PNG", "ru": "Сохранить QR как PNG"},
            "group_color_picker": {"en": "Color Picker", "ru": "Выбор цвета"},
            "btn_pick_color": {"en": "Pick Color", "ru": "Выбрать цвет"},
            "group_color_converter": {"en": "Color Converter", "ru": "Конвертер цвета"},
            "label_hex": {"en": "HEX:", "ru": "HEX:"},
            "label_rgb": {"en": "RGB:", "ru": "RGB:"},
            "label_hsl": {"en": "HSL:", "ru": "HSL:"},
            "btn_convert": {"en": "Convert", "ru": "Конвертировать"},
            "placeholder_hex": {"en": "#RRGGBB", "ru": "#RRGGBB"},
            "placeholder_rgb": {"en": "R, G, B", "ru": "R, G, B"},
            "copied_clipboard": {"en": "Copied to clipboard", "ru": "Скопировано в буфер обмена"},
            "error": {"en": "Error", "ru": "Ошибка"},
        }

        # Prepare UI
        self.setup_styles()
        self.setup_ui()

        # place to store last QR image bytes
        self._last_qr_image_bytes = None
        self.qr_thread = None

    # Translate helper
    def tr_text(self, key):
        entry = self.translations.get(key)
        if not entry:
            return key
        return entry.get(self.current_lang, entry.get("en", key))

    def setup_styles(self):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(40, 44, 52))
        dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(30, 34, 42))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(40, 44, 52))
        dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(61, 142, 255))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(61, 142, 255))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        # placeholder text color default isn't guaranteed; set a general placeholder color too
        dark_palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#6e7680"))
        QApplication.instance().setPalette(dark_palette)
        QApplication.instance().setFont(QFont("Segoe UI", 10))

    def setup_ui(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        self.setWindowIcon(QIcon("icon.ico"))
        self.setWindowTitle(self.tr_text("title"))
        self.setGeometry(100, 100, 1200, 860)

        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(14, 14, 14, 14)

        # Header
        header_layout = QHBoxLayout()
        header_icon = QLabel()
        pix = QPixmap(icon_path)
        if not pix.isNull():
            icon_size = 28
            scaled = pix.scaled(icon_size, icon_size,
                                Qt.AspectRatioMode.KeepAspectRatio,
                                Qt.TransformationMode.SmoothTransformation)
            header_icon.setPixmap(scaled)
            header_icon.setFixedSize(icon_size, icon_size)
        else:
            header_icon.setFixedSize(28, 28)

        self.header_label = QLabel(self.tr_text("title"))
        self.header_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self.header_label.setStyleSheet("color: #61a0ff;")
        self.header_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        title_layout = QHBoxLayout()
        title_layout.setSpacing(8)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.addWidget(header_icon)
        title_layout.addWidget(self.header_label)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()

        self.lang_selector = QComboBox()
        self.lang_selector.addItem(self.translations["lang_en"][self.current_lang], "en")
        self.lang_selector.addItem(self.translations["lang_ru"][self.current_lang], "ru")
        idx = 0 if self.current_lang == "en" else 1
        self.lang_selector.setCurrentIndex(idx)
        self.lang_selector.currentIndexChanged.connect(self.on_lang_change)
        self.lang_selector.setFixedWidth(120)
        header_layout.addWidget(self.lang_selector)

        main_layout.addLayout(header_layout)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setDocumentMode(True)
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                background: #2c313c;
                color: #abb2bf;
                padding: 8px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #61a0ff;
                color: #282c34;
            }
        """)

        # Create tabs
        self.create_text_tools_tab()
        self.create_encoding_tab()
        self.create_hash_tab()
        self.create_json_tab()
        self.create_timestamp_tab()
        self.create_network_tab()
        self.create_generator_tab()
        self.create_color_tab()

        main_layout.addWidget(self.tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage(self.tr_text("ready"))

    # ---------------------------
    # Language change handling
    # ---------------------------
    def on_lang_change(self, index):
        data = self.lang_selector.itemData(index)
        if not data:
            return
        self.current_lang = data
        self.settings.setValue("language", self.current_lang)
        self.update_language()

    def update_language(self):
        self.setWindowTitle(self.tr_text("title"))
        self.header_label.setText(self.tr_text("title"))
        self.status_bar.showMessage(self.tr_text("ready"))

        self.lang_selector.setItemText(0, self.translations["lang_en"][self.current_lang])
        self.lang_selector.setItemText(1, self.translations["lang_ru"][self.current_lang])
        idx = 0 if self.current_lang == "en" else 1
        self.lang_selector.blockSignals(True)
        self.lang_selector.setCurrentIndex(idx)
        self.lang_selector.blockSignals(False)

        self.tabs.setTabText(0, self.tr_text("tab_text"))
        self.tabs.setTabText(1, self.tr_text("tab_encoding"))
        self.tabs.setTabText(2, self.tr_text("tab_hashing"))
        self.tabs.setTabText(3, self.tr_text("tab_json"))
        self.tabs.setTabText(4, self.tr_text("tab_time"))
        self.tabs.setTabText(5, self.tr_text("tab_network"))
        self.tabs.setTabText(6, self.tr_text("tab_generators"))
        self.tabs.setTabText(7, self.tr_text("tab_colors"))

        # Text tab
        self.input_group.setTitle(self.tr_text("group_input_text"))
        self.transform_group.setTitle(self.tr_text("group_transforms"))
        self.result_group.setTitle(self.tr_text("group_result"))
        self.text_input.setPlaceholderText(self.tr_text("placeholder_text_input"))
        for key, btn in self.text_buttons.items():
            btn.setText(self.tr_text(key))
        self.regex_pattern.setPlaceholderText(self.tr_text("regex_pattern"))
        self.regex_replacement.setPlaceholderText(self.tr_text("regex_replacement"))
        self.regex_apply_btn.setText(self.tr_text("regex_apply"))

        # Encoding tab
        self.encoding_group.setTitle(self.tr_text("group_encoding_type"))
        self.encode_input_group.setTitle(self.tr_text("group_encoding_input"))
        self.encoding_type_combo.clear()
        self.encoding_type_combo.addItems([
            self.translations["enc_Base64"][self.current_lang],
            self.translations["enc_URL"][self.current_lang],
            self.translations["enc_Base32"][self.current_lang],
            self.translations["enc_ASCII"][self.current_lang],
            self.translations["enc_Hex"][self.current_lang],
            self.translations["enc_Base85"][self.current_lang],
            self.translations["enc_Base58"][self.current_lang],
        ])
        self.encode_input.setPlaceholderText(self.tr_text("placeholder_encoding_input"))
        self.encode_btn.setText(self.tr_text("btn_encode"))
        self.decode_btn.setText(self.tr_text("btn_decode"))

        # Hash tab
        self.hash_algo_group.setTitle(self.tr_text("group_hash_algorithm"))
        self.hash_input_group.setTitle(self.tr_text("group_hash_input"))
        self.hash_algo.clear()
        self.hash_algo.addItems([
            self.translations["hash_MD5"][self.current_lang],
            self.translations["hash_SHA1"][self.current_lang],
            self.translations["hash_SHA256"][self.current_lang],
            self.translations["hash_SHA512"][self.current_lang],
            self.translations["hash_BLAKE2b"][self.current_lang],
            self.translations["hash_BLAKE2s"][self.current_lang],
        ])
        self.hash_input.setPlaceholderText(self.tr_text("placeholder_hash_input"))
        self.gen_hash_btn.setText(self.tr_text("btn_generate_hash"))
        self.hmac_key_input.setPlaceholderText(self.tr_text("hmac_key"))

        # JSON tab
        self.json_input_group.setTitle(self.tr_text("group_json_input"))
        self.format_json_btn.setText(self.tr_text("btn_format_json"))
        self.minify_json_btn.setText(self.tr_text("btn_minify_json"))
        self.validate_json_btn.setText(self.tr_text("btn_validate_json"))
        self.json_input.setPlaceholderText(self.tr_text("placeholder_json_input"))

        # Time tab
        self.timestamp_group.setTitle(self.tr_text("group_timestamp_converter"))
        self.timestamp_input.setPlaceholderText(self.tr_text("placeholder_timestamp"))
        self.date_input.setPlaceholderText(self.tr_text("placeholder_datetime"))
        self.convert_to_date_btn.setText(self.tr_text("btn_to_date"))
        self.convert_to_timestamp_btn.setText(self.tr_text("btn_to_timestamp"))
        self.gen_unix_btn.setText(self.tr_text("btn_generate_unix"))
        self.gen_iso_btn.setText(self.tr_text("btn_generate_iso"))
        self.copy_time_btn.setText(self.tr_text("btn_copy_time"))
        self.date1_input.setPlaceholderText(self.tr_text("placeholder_datetime"))
        self.date2_input.setPlaceholderText(self.tr_text("placeholder_datetime"))
        self.calc_diff_btn.setText(self.tr_text("btn_calc_diff"))

        # Network tab
        self.ip_group.setTitle(self.tr_text("group_ip_lookup"))
        self.ping_group.setTitle(self.tr_text("group_ping_tool"))
        self.host_input.setPlaceholderText("example.com")
        self.ping_host_input.setPlaceholderText("example.com or IP")
        self.lookup_ip_btn.setText(self.tr_text("btn_lookup_ip"))
        self.ping_btn.setText(self.tr_text("btn_ping"))
        self.http_send_btn.setText(self.tr_text("http_send"))
        self.http_url_input.setPlaceholderText(self.tr_text("http_url"))

        # Generators tab
        self.pass_group.setTitle(self.tr_text("group_password_generator"))
        self.uuid_group.setTitle(self.tr_text("group_uuid_generator"))
        self.pass_length_label.setText(self.tr_text("label_length"))
        self.include_label.setText(self.tr_text("label_include"))
        self.include_upper.setItemText(0, self.tr_text("opt_uppercase"))
        self.include_upper.setItemText(1, self.tr_text("opt_no_uppercase"))
        self.include_digits.setItemText(0, self.tr_text("opt_digits"))
        self.include_digits.setItemText(1, self.tr_text("opt_no_digits"))
        self.include_symbols.setItemText(0, self.tr_text("opt_symbols"))
        self.include_symbols.setItemText(1, self.tr_text("opt_no_symbols"))
        self.gen_pass_btn.setText(self.tr_text("btn_generate_password"))
        self.gen_uuid_btn.setText(self.tr_text("btn_generate_uuid"))
        self.qr_input.setPlaceholderText(self.tr_text("qr_input"))
        self.gen_qr_btn.setText(self.tr_text("btn_generate_qr"))
        self.save_qr_btn.setText(self.tr_text("save_qr_png"))
        if not HAS_QRCODE:
            self.gen_qr_btn.setEnabled(False)
            self.save_qr_btn.setEnabled(False)
            self.qr_status.setText(self.tr_text("qr_requires"))

        # Colors tab
        self.picker_group.setTitle(self.tr_text("group_color_picker"))
        self.converter_group.setTitle(self.tr_text("group_color_converter"))
        self.color_picker_btn.setText(self.tr_text("btn_pick_color"))
        self.convert_hex_btn.setText(self.tr_text("btn_convert"))
        self.convert_rgb_btn.setText(self.tr_text("btn_convert"))
        self.hex_input.setPlaceholderText(self.tr_text("placeholder_hex"))
        self.rgb_input.setPlaceholderText(self.tr_text("placeholder_rgb"))

    # ---------------------------
    # Create tabs (full UI including new features)
    # ---------------------------
    def create_text_tools_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Input group
        self.input_group = QGroupBox(self.tr_text("group_input_text"))
        input_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText(self.tr_text("placeholder_text_input"))
        self.text_input.setStyleSheet(self._textedit_style())
        input_layout.addWidget(self.text_input)
        self.input_group.setLayout(input_layout)

        # Transform group
        self.transform_group = QGroupBox(self.tr_text("group_transforms"))
        transform_layout = QGridLayout()

        transforms = [
            ("upper_case", self.to_upper),
            ("lower_case", self.to_lower),
            ("swap_case", self.swap_case),
            ("camel_case", self.to_camel_case),
            ("snake_case", self.to_snake_case),
            ("remove_spaces", self.remove_spaces),
            ("trim_whitespace", self.trim_whitespace),
            ("reverse_text", self.reverse_text),
            ("wrap_quotes", self.wrap_quotes),
            ("count_chars", self.count_chars),
            ("clear", self.clear_text),
        ]

        self.text_buttons = {}
        row, col = 0, 0
        for key, handler in transforms:
            btn = self._styled_button(self.tr_text(key), handler)
            transform_layout.addWidget(btn, row, col)
            self.text_buttons[key] = btn
            col += 1
            if col > 2:
                col = 0
                row += 1

        # RegEx controls (new)
        regex_label = QLabel(self.tr_text("regex_pattern"))
        self.regex_pattern = QLineEdit()
        self.regex_pattern.setPlaceholderText(self.tr_text("regex_pattern"))
        # make placeholder lighter via palette
        pal = self.regex_pattern.palette()
        pal.setColor(QPalette.ColorRole.PlaceholderText, QColor("#9aa7b3"))
        self.regex_pattern.setPalette(pal)
        self.regex_pattern.setStyleSheet(self._linedit_style())

        regex_repl_label = QLabel(self.tr_text("regex_replacement"))
        self.regex_replacement = QLineEdit()
        self.regex_replacement.setPlaceholderText(self.tr_text("regex_replacement"))
        pal2 = self.regex_replacement.palette()
        pal2.setColor(QPalette.ColorRole.PlaceholderText, QColor("#9aa7b3"))
        self.regex_replacement.setPalette(pal2)
        self.regex_replacement.setStyleSheet(self._linedit_style())

        # flags
        self.regex_icase = QCheckBox("i (IGNORECASE)")
        self.regex_multiline = QCheckBox("m (MULTILINE)")
        self.regex_dotall = QCheckBox("s (DOTALL)")
        self.regex_apply_btn = self._styled_button(self.tr_text("regex_apply"), self.apply_regex_replace)

        # add regex widgets under transforms
        transform_layout.addWidget(regex_label, row + 1, 0)
        transform_layout.addWidget(self.regex_pattern, row + 1, 1, 1, 2)
        transform_layout.addWidget(regex_repl_label, row + 2, 0)
        transform_layout.addWidget(self.regex_replacement, row + 2, 1, 1, 2)
        transform_layout.addWidget(self.regex_icase, row + 3, 0)
        transform_layout.addWidget(self.regex_multiline, row + 3, 1)
        transform_layout.addWidget(self.regex_dotall, row + 3, 2)
        transform_layout.addWidget(self.regex_apply_btn, row + 4, 0, 1, 3)

        self.transform_group.setLayout(transform_layout)

        # Output group
        self.result_group = QGroupBox(self.tr_text("group_result"))
        output_layout = QVBoxLayout()
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        self.text_output.setStyleSheet(self._textedit_style(readonly=True))
        output_layout.addWidget(self.text_output)
        self.result_group.setLayout(output_layout)

        layout.addWidget(self.input_group)
        layout.addWidget(self.transform_group)
        layout.addWidget(self.result_group)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_text"))

    def create_encoding_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Encoding type selection
        self.encoding_group = QGroupBox(self.tr_text("group_encoding_type"))
        encoding_layout = QHBoxLayout()
        self.encoding_type_combo = QComboBox()
        self.encoding_type_combo.addItems([
            self.translations["enc_Base64"][self.current_lang],
            self.translations["enc_URL"][self.current_lang],
            self.translations["enc_Base32"][self.current_lang],
            self.translations["enc_ASCII"][self.current_lang],
            self.translations["enc_Hex"][self.current_lang],
            self.translations["enc_Base85"][self.current_lang],
            self.translations["enc_Base58"][self.current_lang],
        ])
        self.encoding_type_combo.setStyleSheet(self._combobox_style())
        encoding_layout.addWidget(self.encoding_type_combo)
        self.encoding_group.setLayout(encoding_layout)

        # Input area
        self.encode_input_group = QGroupBox(self.tr_text("group_encoding_input"))
        encode_input_layout = QVBoxLayout()
        self.encode_input = QTextEdit()
        self.encode_input.setPlaceholderText(self.tr_text("placeholder_encoding_input"))
        self.encode_input.setStyleSheet(self._textedit_style())
        encode_input_layout.addWidget(self.encode_input)
        self.encode_input_group.setLayout(encode_input_layout)

        # Action buttons
        action_layout = QHBoxLayout()
        self.encode_btn = self._styled_button(self.tr_text("btn_encode"), self.encode)
        self.decode_btn = self._styled_button(self.tr_text("btn_decode"), self.decode)
        action_layout.addWidget(self.encode_btn)
        action_layout.addWidget(self.decode_btn)

        # Output
        self.encode_output = QTextEdit()
        self.encode_output.setReadOnly(True)
        self.encode_output.setStyleSheet(self._textedit_style(readonly=True))

        layout.addWidget(self.encoding_group)
        layout.addWidget(self.encode_input_group)
        layout.addLayout(action_layout)
        layout.addWidget(self.encode_output)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_encoding"))

    def create_hash_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Algorithm selection
        self.hash_algo_group = QGroupBox(self.tr_text("group_hash_algorithm"))
        algo_layout = QHBoxLayout()
        self.hash_algo = QComboBox()
        self.hash_algo.addItems([
            self.translations["hash_MD5"][self.current_lang],
            self.translations["hash_SHA1"][self.current_lang],
            self.translations["hash_SHA256"][self.current_lang],
            self.translations["hash_SHA512"][self.current_lang],
            self.translations["hash_BLAKE2b"][self.current_lang],
            self.translations["hash_BLAKE2s"][self.current_lang],
        ])
        self.hash_algo.setStyleSheet(self._combobox_style())
        algo_layout.addWidget(self.hash_algo)
        self.hash_algo_group.setLayout(algo_layout)

        # Input
        self.hash_input_group = QGroupBox(self.tr_text("group_hash_input"))
        hash_input_layout = QVBoxLayout()
        self.hash_input = QTextEdit()
        self.hash_input.setPlaceholderText(self.tr_text("placeholder_hash_input"))
        self.hash_input.setStyleSheet(self._textedit_style())
        hash_input_layout.addWidget(self.hash_input)

        # HMAC / key
        self.hmac_key_input = QLineEdit()
        self.hmac_key_input.setPlaceholderText(self.tr_text("hmac_key"))
        self.hmac_key_input.setStyleSheet(self._linedit_style())
        hash_input_layout.addWidget(self.hmac_key_input)

        self.hash_input_group.setLayout(hash_input_layout)

        # Generate button and result
        gen_layout = QHBoxLayout()
        self.gen_hash_btn = self._styled_button(self.tr_text("btn_generate_hash"), self.generate_hash)
        self.hash_result = QLineEdit()
        self.hash_result.setReadOnly(True)
        self.hash_result.setStyleSheet(self._outputline_style())
        gen_layout.addWidget(self.gen_hash_btn)
        gen_layout.addWidget(self.hash_result)

        layout.addWidget(self.hash_algo_group)
        layout.addWidget(self.hash_input_group)
        layout.addLayout(gen_layout)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_hashing"))

    def create_json_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # JSON input
        self.json_input_group = QGroupBox(self.tr_text("group_json_input"))
        json_input_layout = QVBoxLayout()
        self.json_input = QTextEdit()
        self.json_input.setPlaceholderText(self.tr_text("placeholder_json_input"))
        self.json_input.setStyleSheet(self._textedit_style())
        json_input_layout.addWidget(self.json_input)
        self.json_input_group.setLayout(json_input_layout)

        # Actions
        action_layout = QHBoxLayout()
        self.format_json_btn = self._styled_button(self.tr_text("btn_format_json"), self.format_json)
        self.minify_json_btn = self._styled_button(self.tr_text("btn_minify_json"), self.minify_json)
        self.validate_json_btn = self._styled_button(self.tr_text("btn_validate_json"), self.validate_json)
        action_layout.addWidget(self.format_json_btn)
        action_layout.addWidget(self.minify_json_btn)
        action_layout.addWidget(self.validate_json_btn)

        # Output
        self.json_output = QTextEdit()
        self.json_output.setReadOnly(True)
        self.json_output.setStyleSheet(self._textedit_style(readonly=True))

        layout.addWidget(self.json_input_group)
        layout.addLayout(action_layout)
        layout.addWidget(self.json_output)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_json"))

    def create_timestamp_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Converter
        self.timestamp_group = QGroupBox(self.tr_text("group_timestamp_converter"))
        converter_layout = QGridLayout()

        converter_layout.addWidget(QLabel(self.tr_text("label_timestamp")), 0, 0)
        self.timestamp_input = QLineEdit()
        self.timestamp_input.setPlaceholderText(self.tr_text("placeholder_timestamp"))
        self.timestamp_input.setStyleSheet(self._linedit_style())
        converter_layout.addWidget(self.timestamp_input, 0, 1)
        self.convert_to_date_btn = self._styled_button(self.tr_text("btn_to_date"), self.timestamp_to_date)
        converter_layout.addWidget(self.convert_to_date_btn, 0, 2)

        converter_layout.addWidget(QLabel(self.tr_text("label_datetime")), 1, 0)
        self.date_input = QLineEdit()
        self.date_input.setPlaceholderText(self.tr_text("placeholder_datetime"))
        self.date_input.setStyleSheet(self._linedit_style())
        converter_layout.addWidget(self.date_input, 1, 1)
        self.convert_to_timestamp_btn = self._styled_button(self.tr_text("btn_to_timestamp"), self.date_to_timestamp)
        converter_layout.addWidget(self.convert_to_timestamp_btn, 1, 2)

        converter_layout.addWidget(QLabel("Result:"), 2, 0)
        self.time_result = QLineEdit()
        self.time_result.setReadOnly(True)
        self.time_result.setStyleSheet(self._outputline_style())
        converter_layout.addWidget(self.time_result, 2, 1, 1, 2)

        self.timestamp_group.setLayout(converter_layout)

        # Generators
        generator_group = QGroupBox()
        generator_group.setTitle("")  # not needed title
        generator_layout = QHBoxLayout()
        self.gen_unix_btn = self._styled_button(self.tr_text("btn_generate_unix"), self.gen_unix_timestamp)
        self.gen_iso_btn = self._styled_button(self.tr_text("btn_generate_iso"), self.gen_iso_time)
        self.copy_time_btn = self._styled_button(self.tr_text("btn_copy_time"), self.copy_time_result)
        generator_layout.addWidget(self.gen_unix_btn)
        generator_layout.addWidget(self.gen_iso_btn)
        generator_layout.addWidget(self.copy_time_btn)
        generator_group.setLayout(generator_layout)

        # Date difference (new)
        diff_group = QGroupBox(self.tr_text("date_diff"))
        diff_layout = QGridLayout()
        self.date1_input = QLineEdit()
        self.date1_input.setPlaceholderText(self.tr_text("placeholder_datetime"))
        self.date2_input = QLineEdit()
        self.date2_input.setPlaceholderText(self.tr_text("placeholder_datetime"))
        self.calc_diff_btn = self._styled_button(self.tr_text("btn_calc_diff"), self.calculate_date_difference)
        self.diff_result = QLineEdit()
        self.diff_result.setReadOnly(True)
        self.diff_result.setStyleSheet(self._outputline_style())
        diff_layout.addWidget(QLabel("Date 1:"), 0, 0)
        diff_layout.addWidget(self.date1_input, 0, 1)
        diff_layout.addWidget(QLabel("Date 2:"), 1, 0)
        diff_layout.addWidget(self.date2_input, 1, 1)
        diff_layout.addWidget(self.calc_diff_btn, 0, 2, 2, 1)
        diff_layout.addWidget(QLabel("Result:"), 2, 0)
        diff_layout.addWidget(self.diff_result, 2, 1, 1, 2)
        diff_group.setLayout(diff_layout)

        layout.addWidget(self.timestamp_group)
        layout.addWidget(generator_group)
        layout.addWidget(diff_group)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_time"))

    def create_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # IP Lookup
        self.ip_group = QGroupBox(self.tr_text("group_ip_lookup"))
        ip_layout = QGridLayout()
        ip_layout.addWidget(QLabel(self.tr_text("label_hostname")), 0, 0)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("example.com")
        self.host_input.setStyleSheet(self._linedit_style())
        ip_layout.addWidget(self.host_input, 0, 1)
        self.lookup_ip_btn = self._styled_button(self.tr_text("btn_lookup_ip"), self.lookup_ip)
        ip_layout.addWidget(self.lookup_ip_btn, 0, 2)

        ip_layout.addWidget(QLabel(self.tr_text("label_ip_address")), 1, 0)
        self.ip_result = QLineEdit()
        self.ip_result.setReadOnly(True)
        self.ip_result.setStyleSheet(self._outputline_style())
        ip_layout.addWidget(self.ip_result, 1, 1, 1, 2)
        self.ip_group.setLayout(ip_layout)

        # Ping
        self.ping_group = QGroupBox(self.tr_text("group_ping_tool"))
        ping_layout = QVBoxLayout()
        ping_host_layout = QHBoxLayout()
        ping_host_layout.addWidget(QLabel(self.tr_text("label_ping_host")))
        self.ping_host_input = QLineEdit()
        self.ping_host_input.setPlaceholderText("example.com or IP")
        self.ping_host_input.setStyleSheet(self._linedit_style())
        ping_host_layout.addWidget(self.ping_host_input)
        self.ping_btn = self._styled_button(self.tr_text("btn_ping"), self.start_ping)
        ping_host_layout.addWidget(self.ping_btn)
        self.ping_output = QTextEdit()
        self.ping_output.setReadOnly(True)
        self.ping_output.setStyleSheet(self._textedit_style(readonly=True))
        ping_layout.addLayout(ping_host_layout)
        ping_layout.addWidget(self.ping_output)
        self.ping_group.setLayout(ping_layout)

        # Simple HTTP client (improved)
        http_group = QGroupBox("HTTP")
        http_layout = QGridLayout()
        http_layout.addWidget(QLabel(self.tr_text("http_url")), 0, 0)
        self.http_url_input = QLineEdit()
        self.http_url_input.setPlaceholderText(self.tr_text("http_url"))
        self.http_url_input.setStyleSheet(self._linedit_style())
        http_layout.addWidget(self.http_url_input, 0, 1, 1, 3)

        http_layout.addWidget(QLabel(self.tr_text("http_method")), 1, 0)
        self.http_method_combo = QComboBox()
        self.http_method_combo.addItems(["GET", "POST", "PUT", "DELETE"])
        self.http_method_combo.setStyleSheet(self._combobox_style())
        http_layout.addWidget(self.http_method_combo, 1, 1)

        http_layout.addWidget(QLabel("Timeout (s):"), 1, 2)
        self.http_timeout_spin = QSpinBox()
        self.http_timeout_spin.setRange(1, 120)
        self.http_timeout_spin.setValue(10)
        self.http_timeout_spin.setFixedWidth(90)
        http_layout.addWidget(self.http_timeout_spin, 1, 3)

        http_layout.addWidget(QLabel("Headers (JSON or Key: Value per line):"), 2, 0, 1, 4)
        self.http_headers_edit = QTextEdit()
        self.http_headers_edit.setPlaceholderText('{"User-Agent": "wDevToolbox/1.0"}\nor\nKey: Value')
        self.http_headers_edit.setFixedHeight(90)
        self.http_headers_edit.setStyleSheet(self._textedit_style())
        http_layout.addWidget(self.http_headers_edit, 3, 0, 1, 4)

        # Auth fields
        http_layout.addWidget(QLabel("Basic auth user:"), 4, 0)
        self.http_auth_user = QLineEdit()
        self.http_auth_user.setStyleSheet(self._linedit_style())
        http_layout.addWidget(self.http_auth_user, 4, 1)
        http_layout.addWidget(QLabel("Password:"), 4, 2)
        self.http_auth_pass = QLineEdit()
        self.http_auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.http_auth_pass.setStyleSheet(self._linedit_style())
        http_layout.addWidget(self.http_auth_pass, 4, 3)

        http_layout.addWidget(QLabel("Bearer token (optional):"), 5, 0)
        self.http_bearer_token = QLineEdit()
        self.http_bearer_token.setStyleSheet(self._linedit_style())
        http_layout.addWidget(self.http_bearer_token, 5, 1, 1, 3)

        # SSL verify
        self.http_verify_checkbox = QCheckBox("Verify SSL")
        self.http_verify_checkbox.setChecked(True)
        http_layout.addWidget(self.http_verify_checkbox, 6, 0)

        # Body
        http_layout.addWidget(QLabel("Body (for POST/PUT):"), 6, 1)
        self.http_body = QTextEdit()
        self.http_body.setPlaceholderText("Raw body (for POST/PUT). If JSON, will try to send as JSON.")
        self.http_body.setStyleSheet(self._textedit_style())
        http_layout.addWidget(self.http_body, 7, 0, 1, 4)

        # Controls
        self.http_send_btn = self._styled_button(self.tr_text("http_send"), self.send_http_request)
        http_layout.addWidget(self.http_send_btn, 8, 0)
        http_layout.addWidget(QLabel("Status code:"), 8, 1)
        self.http_status = QLineEdit()
        self.http_status.setReadOnly(True)
        self.http_status.setStyleSheet(self._outputline_style())
        http_layout.addWidget(self.http_status, 8, 2)
        http_layout.addWidget(QLabel(self.tr_text("http_result")), 9, 0)
        self.http_result_view = QTextEdit()
        self.http_result_view.setReadOnly(True)
        self.http_result_view.setStyleSheet(self._textedit_style(readonly=True))
        http_layout.addWidget(self.http_result_view, 10, 0, 1, 4)

        http_group.setLayout(http_layout)

        # disable HTTP if requests not available
        if not HAS_REQUESTS:
            self.http_send_btn.setEnabled(False)
            self.http_result_view.setPlainText(self.tr_text("http_requires_requests"))

        layout.addWidget(self.ip_group)
        layout.addWidget(self.ping_group)
        layout.addWidget(http_group)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_network"))

    def create_generator_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Password generator
        self.pass_group = QGroupBox(self.tr_text("group_password_generator"))
        pass_layout = QGridLayout()

        self.pass_length_label = QLabel(self.tr_text("label_length"))
        self.pass_length = QLineEdit("16")
        self.pass_length.setFixedWidth(70)
        self.pass_length.setStyleSheet(self._linedit_style())
        pass_layout.addWidget(self.pass_length_label, 0, 0)
        pass_layout.addWidget(self.pass_length, 0, 1)

        self.include_label = QLabel(self.tr_text("label_include"))
        self.include_upper = QComboBox()
        self.include_upper.addItems([self.tr_text("opt_uppercase"), self.tr_text("opt_no_uppercase")])
        self.include_digits = QComboBox()
        self.include_digits.addItems([self.tr_text("opt_digits"), self.tr_text("opt_no_digits")])
        self.include_symbols = QComboBox()
        self.include_symbols.addItems([self.tr_text("opt_symbols"), self.tr_text("opt_no_symbols")])
        self.include_upper.setStyleSheet(self._combobox_style())
        self.include_digits.setStyleSheet(self._combobox_style())
        self.include_symbols.setStyleSheet(self._combobox_style())

        pass_layout.addWidget(self.include_label, 1, 0)
        pass_layout.addWidget(self.include_upper, 1, 1)
        pass_layout.addWidget(self.include_digits, 1, 2)
        pass_layout.addWidget(self.include_symbols, 1, 3)

        self.gen_pass_btn = self._styled_button(self.tr_text("btn_generate_password"), self.generate_password)
        pass_layout.addWidget(self.gen_pass_btn, 2, 0, 1, 4)

        self.password_result = QLineEdit()
        self.password_result.setReadOnly(True)
        self.password_result.setStyleSheet(self._outputline_style())
        pass_layout.addWidget(self.password_result, 3, 0, 1, 4)

        self.pass_group.setLayout(pass_layout)

        # UUID generator
        self.uuid_group = QGroupBox(self.tr_text("group_uuid_generator"))
        uuid_layout = QHBoxLayout()
        self.gen_uuid_btn = self._styled_button(self.tr_text("btn_generate_uuid"), self.generate_uuid)
        self.uuid_result = QLineEdit()
        self.uuid_result.setReadOnly(True)
        self.uuid_result.setStyleSheet(self._outputline_style())
        uuid_layout.addWidget(self.gen_uuid_btn)
        uuid_layout.addWidget(self.uuid_result)
        self.uuid_group.setLayout(uuid_layout)

        # QR generator (new)
        qr_group = QGroupBox("QR Code")
        qr_layout = QHBoxLayout()
        self.qr_input = QLineEdit()
        self.qr_input.setPlaceholderText(self.tr_text("qr_input"))
        self.qr_input.setStyleSheet(self._linedit_style())
        self.gen_qr_btn = self._styled_button(self.tr_text("btn_generate_qr"), self.generate_qr)
        self.qr_label = QLabel()
        self.qr_label.setFixedSize(160, 160)
        self.qr_label.setStyleSheet("background:#242629; border:1px solid #3e4451;")
        self.qr_status = QLabel("")
        self.save_qr_btn = self._styled_button(self.tr_text("save_qr_png"), self.save_qr_png)
        if not HAS_QRCODE:
            self.gen_qr_btn.setEnabled(False)
            self.save_qr_btn.setEnabled(False)
        qr_layout.addWidget(self.qr_input)
        qr_layout.addWidget(self.gen_qr_btn)
        qr_layout.addWidget(self.save_qr_btn)
        qr_layout.addWidget(self.qr_label)
        qr_layout.addWidget(self.qr_status)
        qr_group.setLayout(qr_layout)

        layout.addWidget(self.pass_group)
        layout.addWidget(self.uuid_group)
        layout.addWidget(qr_group)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_generators"))

    def create_color_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Color picker
        self.picker_group = QGroupBox(self.tr_text("group_color_picker"))
        picker_layout = QHBoxLayout()
        self.color_picker_btn = self._styled_button(self.tr_text("btn_pick_color"), self.pick_color)
        self.color_preview = QLabel()
        self.color_preview.setFixedSize(60, 60)
        self.color_preview.setStyleSheet("background-color: #61a0ff; border-radius: 4px;")
        picker_layout.addWidget(self.color_picker_btn)
        picker_layout.addWidget(self.color_preview)
        self.picker_group.setLayout(picker_layout)

        # Converter
        self.converter_group = QGroupBox(self.tr_text("group_color_converter"))
        converter_layout = QGridLayout()
        converter_layout.addWidget(QLabel(self.tr_text("label_hex")), 0, 0)
        self.hex_input = QLineEdit()
        self.hex_input.setPlaceholderText(self.tr_text("placeholder_hex"))
        self.hex_input.setStyleSheet(self._linedit_style())
        converter_layout.addWidget(self.hex_input, 0, 1)
        self.convert_hex_btn = self._styled_button(self.tr_text("btn_convert"), self.convert_hex)
        converter_layout.addWidget(self.convert_hex_btn, 0, 2)

        converter_layout.addWidget(QLabel(self.tr_text("label_rgb")), 1, 0)
        self.rgb_input = QLineEdit()
        self.rgb_input.setPlaceholderText(self.tr_text("placeholder_rgb"))
        self.rgb_input.setStyleSheet(self._linedit_style())
        converter_layout.addWidget(self.rgb_input, 1, 1)
        self.convert_rgb_btn = self._styled_button(self.tr_text("btn_convert"), self.convert_rgb)
        converter_layout.addWidget(self.convert_rgb_btn, 1, 2)

        converter_layout.addWidget(QLabel(self.tr_text("label_hsl")), 2, 0)
        self.hsl_output = QLineEdit()
        self.hsl_output.setReadOnly(True)
        self.hsl_output.setStyleSheet(self._outputline_style())
        converter_layout.addWidget(self.hsl_output, 2, 1, 1, 2)

        converter_layout.addWidget(QLabel("Result:"), 3, 0)
        self.color_result = QLineEdit()
        self.color_result.setReadOnly(True)
        self.color_result.setStyleSheet(self._outputline_style())
        converter_layout.addWidget(self.color_result, 3, 1, 1, 2)

        self.converter_group.setLayout(converter_layout)

        layout.addWidget(self.picker_group)
        layout.addWidget(self.converter_group)
        tab.setLayout(layout)
        self.tabs.addTab(tab, self.tr_text("tab_colors"))

    # ---------------------------
    # Styles & helpers
    # ---------------------------
    def _styled_button(self, text, handler):
        btn = QPushButton(text)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #61a0ff;
                color: #282c34;
                border: none;
                padding: 8px 14px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #4d8eff; }
            QPushButton:pressed { background-color: #3a7bff; }
        """)
        btn.clicked.connect(handler)
        return btn

    def _textedit_style(self, readonly=False):
        base = """
            QTextEdit {
                background-color: #2c313c;
                color: #abb2bf;
                border: 1px solid #3e4451;
                border-radius: 6px;
                padding: 8px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
        """
        if readonly:
            base += "QTextEdit { background-color: #242629; }"
        return base

    def _linedit_style(self):
        return """
            QLineEdit {
                background-color: #2c313c;
                color: #abb2bf;
                border: 1px solid #3e4451;
                border-radius: 6px;
                padding: 6px;
            }
        """

    def _outputline_style(self):
        return """
            QLineEdit {
                background-color: #242629;
                color: #abb2bf;
                border: 1px solid #3e4451;
                border-radius: 6px;
                padding: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
        """

    def _combobox_style(self):
        return """
            QComboBox {
                background-color: #2c313c;
                color: #abb2bf;
                border: 1px solid #3e4451;
                border-radius: 6px;
                padding: 6px;
            }
        """

    # ---------------------------
    # Text transformations
    # ---------------------------
    def to_upper(self):
        self.text_output.setPlainText(self.text_input.toPlainText().upper())

    def to_lower(self):
        self.text_output.setPlainText(self.text_input.toPlainText().lower())

    def swap_case(self):
        self.text_output.setPlainText(self.text_input.toPlainText().swapcase())

    def to_camel_case(self):
        text = self.text_input.toPlainText()
        words = re.split(r'\s+|[_\-]+', text.strip())
        if not words:
            self.text_output.setPlainText("")
            return
        first = words[0].lower()
        rest = ''.join(w.capitalize() for w in words[1:] if w)
        self.text_output.setPlainText(first + rest)

    def to_snake_case(self):
        text = self.text_input.toPlainText().strip()
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', text)
        s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1)
        res = re.sub(r'[\s\-]+', '_', s2).lower()
        self.text_output.setPlainText(res)

    def remove_spaces(self):
        text = self.text_input.toPlainText()
        self.text_output.setPlainText(text.replace(" ", "").replace("\n", ""))

    def trim_whitespace(self):
        text = self.text_input.toPlainText()
        self.text_output.setPlainText(text.strip())

    def reverse_text(self):
        text = self.text_input.toPlainText()
        self.text_output.setPlainText(text[::-1])

    def wrap_quotes(self):
        text = self.text_input.toPlainText()
        self.text_output.setPlainText('"' + text.replace('"', r'\"') + '"')

    def count_chars(self):
        text = self.text_input.toPlainText()
        chars = len(text)
        # use regex for words (avoid double split)
        words = len(re.findall(r'\S+', text))
        lines = text.count('\n') + (1 if text else 0)

        self.translations.update({
            "characters": {"en": "Characters", "ru": "Символов"},
            "words": {"en": "Words", "ru": "Слов"},
            "lines": {"en": "Lines", "ru": "Строк"},
        })

        self.text_output.setPlainText(f"{self.tr_text('characters')}: {chars}\n{self.tr_text('words')}: {words}\n{self.tr_text('lines')}: {lines}")

    def clear_text(self):
        self.text_input.clear()
        self.text_output.clear()

    def apply_regex_replace(self):
        """
        Apply RegEx replacement to the input text.
        First attempts to compile the pattern with selected flags to surface syntax errors early.
        """
        pattern = self.regex_pattern.text()
        repl = self.regex_replacement.text()
        flags = 0
        if self.regex_icase.isChecked():
            flags |= re.IGNORECASE
        if self.regex_multiline.isChecked():
            flags |= re.MULTILINE
        if self.regex_dotall.isChecked():
            flags |= re.DOTALL

        if not pattern:
            self.text_output.setPlainText(self.tr_text("error") + ": empty pattern")
            return

        try:
            compiled = re.compile(pattern, flags=flags)
        except re.error as e:
            self.text_output.setPlainText(f"{self.tr_text('error')}: invalid regex: {str(e)}")
            return

        try:
            src = self.text_input.toPlainText()
            result = compiled.sub(repl, src)
            self.text_output.setPlainText(result)
        except Exception as e:
            self.text_output.setPlainText(f"{self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # Encoding methods
    # ---------------------------
    def encode(self):
        text = self.encode_input.toPlainText()
        encoding = self.encoding_type_combo.currentText().lower()
        try:
            if encoding.startswith("base64"):
                result = base64.b64encode(text.encode()).decode()
            elif encoding.startswith("url"):
                result = urllib.parse.quote(text)
            elif encoding.startswith("base32"):
                result = base64.b32encode(text.encode()).decode()
            elif encoding.startswith("ascii"):
                result = ' '.join(str(ord(char)) for char in text)
            elif encoding.startswith("hex"):
                result = text.encode().hex()
            elif encoding.startswith("base85"):
                result = base64.b85encode(text.encode()).decode()
            elif encoding.startswith("base58"):
                result = base58_encode(text.encode())
            else:
                result = "Unsupported encoding"
            self.encode_output.setPlainText(result)
        except Exception as e:
            self.encode_output.setPlainText(f"{self.tr_text('error')}: {str(e)}")

    def decode(self):
        text = self.encode_input.toPlainText()
        encoding = self.encoding_type_combo.currentText().lower()
        try:
            if encoding.startswith("base64"):
                result = base64.b64decode(text).decode()
            elif encoding.startswith("url"):
                result = urllib.parse.unquote(text)
            elif encoding.startswith("base32"):
                result = base64.b32decode(text).decode()
            elif encoding.startswith("ascii"):
                result = ''.join(chr(int(x)) for x in text.split())
            elif encoding.startswith("hex"):
                result = bytes.fromhex(text).decode()
            elif encoding.startswith("base85"):
                result = base64.b85decode(text.encode()).decode()
            elif encoding.startswith("base58"):
                result = base58_decode(text).decode()
            else:
                result = "Unsupported encoding"
            self.encode_output.setPlainText(result)
        except Exception as e:
            self.encode_output.setPlainText(f"{self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # Hashing methods
    # ---------------------------
    def generate_hash(self):
        """
        Generate hash or HMAC for given input.
        Supports MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE2s.
        If an HMAC key is supplied:
          - For MD5/SHA family: use HMAC with the selected digest.
          - For BLAKE2b/BLAKE2s: use keyed BLAKE2 digest (hashlib.blake2b(..., key=...)),
            because using hmac with blake2 is not standard and BLAKE2 provides keyed mode.
        """
        text = self.hash_input.toPlainText()
        algo = self.hash_algo.currentText().lower()
        key = self.hmac_key_input.text()

        if not text:
            return
        try:
            # HMAC / keyed flow
            if key:
                key_bytes = key.encode()
                msg = text.encode()
                if algo.startswith("md5"):
                    digest = hmac.new(key_bytes, msg, hashlib.md5).hexdigest()
                elif algo.startswith("sha-1") or algo.startswith("sha1"):
                    digest = hmac.new(key_bytes, msg, hashlib.sha1).hexdigest()
                elif algo.startswith("sha-256") or algo.startswith("sha256"):
                    digest = hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()
                elif algo.startswith("sha-512") or algo.startswith("sha512"):
                    digest = hmac.new(key_bytes, msg, hashlib.sha512).hexdigest()
                elif algo.startswith("blake2b"):
                    # Use keyed BLAKE2b (recommended method for keyed hashing)
                    digest = hashlib.blake2b(msg, key=key_bytes).hexdigest()
                elif algo.startswith("blake2s"):
                    digest = hashlib.blake2s(msg, key=key_bytes).hexdigest()
                else:
                    self.hash_result.setText("Unsupported algorithm")
                    return
            else:
                # plain hash
                if algo.startswith("md5"):
                    digest = hashlib.md5(text.encode()).hexdigest()
                elif algo.startswith("sha-1") or algo.startswith("sha1"):
                    digest = hashlib.sha1(text.encode()).hexdigest()
                elif algo.startswith("sha-256") or algo.startswith("sha256"):
                    digest = hashlib.sha256(text.encode()).hexdigest()
                elif algo.startswith("sha-512") or algo.startswith("sha512"):
                    digest = hashlib.sha512(text.encode()).hexdigest()
                elif algo.startswith("blake2b"):
                    digest = hashlib.blake2b(text.encode()).hexdigest()
                elif algo.startswith("blake2s"):
                    digest = hashlib.blake2s(text.encode()).hexdigest()
                else:
                    digest = "Unsupported algorithm"
            self.hash_result.setText(digest)
        except Exception as e:
            self.hash_result.setText(f"{self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # JSON methods
    # ---------------------------
    def format_json(self):
        try:
            data = json.loads(self.json_input.toPlainText())
            self.json_output.setPlainText(json.dumps(data, indent=4, ensure_ascii=False))
        except Exception as e:
            self.json_output.setPlainText(f"{self.tr_text('error')}: {str(e)}")

    def minify_json(self):
        try:
            data = json.loads(self.json_input.toPlainText())
            self.json_output.setPlainText(json.dumps(data, separators=(',', ':')))
        except Exception as e:
            self.json_output.setPlainText(f"{self.tr_text('error')}: {str(e)}")

    def validate_json(self):
        try:
            json.loads(self.json_input.toPlainText())
            self.json_output.setPlainText(self.tr_text("json_valid"))
        except Exception as e:
            self.json_output.setPlainText(f"❌ {self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # Time methods
    # ---------------------------
    def timestamp_to_date(self):
        try:
            timestamp = int(self.timestamp_input.text())
            dt = datetime.fromtimestamp(timestamp)
            self.time_result.setText(dt.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            self.time_result.setText(f"{self.tr_text('error')}: {str(e)}")

    def date_to_timestamp(self):
        try:
            dt = datetime.strptime(self.date_input.text(), "%Y-%m-%d %H:%M:%S")
            self.time_result.setText(str(int(dt.timestamp())))
        except Exception as e:
            self.time_result.setText(f"{self.tr_text('error')}: {str(e)}")

    def gen_unix_timestamp(self):
        self.time_result.setText(str(int(datetime.now().timestamp())))

    def gen_iso_time(self):
        self.time_result.setText(datetime.now().isoformat())

    def copy_time_result(self):
        clipboard: QClipboard = QApplication.clipboard()
        clipboard.setText(self.time_result.text())
        self.status_bar.showMessage(self.tr_text("copied_clipboard"), 2000)

    def calculate_date_difference(self):
        d1 = self.date1_input.text().strip()
        d2 = self.date2_input.text().strip()
        try:
            dt1 = datetime.strptime(d1, "%Y-%m-%d %H:%M:%S")
            dt2 = datetime.strptime(d2, "%Y-%m-%d %H:%M:%S")
            delta = abs(dt2 - dt1)
            days = delta.days
            seconds = delta.seconds
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.diff_result.setText(f"{days} days, {hours}h {minutes}m {seconds}s")
        except Exception as e:
            self.diff_result.setText(f"{self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # Network methods
    # ---------------------------
    def lookup_ip(self):
        host = self.host_input.text().strip()
        if not host:
            return
        try:
            ip = socket.gethostbyname(host)
            self.ip_result.setText(ip)
        except Exception as e:
            self.ip_result.setText(f"{self.tr_text('error')}: {str(e)}")

    def start_ping(self):
        host = self.ping_host_input.text().strip()
        if not host:
            return
        self.ping_output.setPlainText(self.tr_text("ready") + "...")
        self.ping_thread = PingThread(host)
        self.ping_thread.result.connect(self.show_ping_result)
        self.ping_thread.start()

    def show_ping_result(self, result):
        self.ping_output.setPlainText(result)

    def _parse_headers_text(self, raw_text: str) -> dict:
        raw = raw_text.strip()
        if not raw:
            return {}
        # Try JSON first
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except Exception:
            pass
        # Fallback to Key: Value per line
        headers = {}
        for line in raw.splitlines():
            if not line.strip():
                continue
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        return headers

    def send_http_request(self):
        """
        Send HTTP request using requests.
        Supports:
         - custom headers (JSON or Key: Value per line)
         - Basic auth user/password
         - Bearer token
         - timeout (seconds)
         - SSL verification toggle
         - automatic handling of JSON body if valid JSON
        Results (status, headers, body) are shown in the HTTP result view.
        """
        if not HAS_REQUESTS:
            self.http_result_view.setPlainText(self.tr_text("http_requires_requests"))
            return
        url = self.http_url_input.text().strip()
        if not url:
            return
        method = self.http_method_combo.currentText()
        timeout = int(self.http_timeout_spin.value())
        headers = self._parse_headers_text(self.http_headers_edit.toPlainText())

        # Authorization: Bearer token overrides Basic header
        bearer = self.http_bearer_token.text().strip()
        if bearer:
            headers['Authorization'] = f"Bearer {bearer}"

        auth_user = self.http_auth_user.text().strip()
        auth_pass = self.http_auth_pass.text()

        verify_ssl = bool(self.http_verify_checkbox.isChecked())

        body_text = self.http_body.toPlainText()
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, auth=(auth_user, auth_pass) if auth_user else None, timeout=timeout, verify=verify_ssl)
            elif method in ("POST", "PUT", "DELETE"):
                # attempt to parse JSON body
                payload = None
                send_json = False
                if body_text.strip():
                    try:
                        payload = json.loads(body_text)
                        send_json = True
                    except Exception:
                        payload = body_text.encode('utf-8')
                        send_json = False

                if method == "POST":
                    if send_json:
                        r = requests.post(url, headers=headers, json=payload, auth=(auth_user, auth_pass) if auth_user else None, timeout=timeout, verify=verify_ssl)
                    else:
                        # ensure Content-Type if not set
                        if isinstance(payload, (bytes, bytearray)) and 'Content-Type' not in {k.title(): v for k, v in headers.items()}:
                            headers.setdefault('Content-Type', 'text/plain; charset=utf-8')
                        r = requests.post(url, headers=headers, data=payload, auth=(auth_user, auth_pass) if auth_user else None, timeout=timeout, verify=verify_ssl)
                elif method == "PUT":
                    if send_json:
                        r = requests.put(url, headers=headers, json=payload, auth=(auth_user, auth_pass) if auth_user else None, timeout=timeout, verify=verify_ssl)
                    else:
                        if isinstance(payload, (bytes, bytearray)) and 'Content-Type' not in {k.title(): v for k, v in headers.items()}:
                            headers.setdefault('Content-Type', 'text/plain; charset=utf-8')
                        r = requests.put(url, headers=headers, data=payload, auth=(auth_user, auth_pass) if auth_user else None, timeout=timeout, verify=verify_ssl)
                else:  # DELETE
                    r = requests.delete(url, headers=headers, auth=(auth_user, auth_pass) if auth_user else None, timeout=timeout, verify=verify_ssl)
            else:
                r = requests.request(method, url, headers=headers, timeout=timeout, verify=verify_ssl)
            # show results
            self.http_status.setText(str(r.status_code))
            headers_text = json.dumps(dict(r.headers), indent=2)
            body = r.text
            response_text = f"--- Response headers ---\n{headers_text}\n\n--- Response body ---\n{body}"
            # ensure showing as plain text (avoid HTML interpretation)
            self.http_result_view.setPlainText(response_text)
        except Exception as e:
            self.http_result_view.setPlainText(f"{self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # Generators methods
    # ---------------------------
    def generate_password(self):
        try:
            length = int(self.pass_length.text())
            if length < 4:
                length = 4
            if length > 256:
                length = 256
        except Exception:
            length = 16

        chars = "abcdefghijklmnopqrstuvwxyz"
        if self.include_upper.currentIndex() == 0:
            chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.include_digits.currentIndex() == 0:
            chars += "0123456789"
        if self.include_symbols.currentIndex() == 0:
            chars += "!@#$%^&*()_-+=<>?"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.password_result.setText(password)

    def generate_uuid(self):
        self.uuid_result.setText(str(uuid.uuid4()))

    def generate_qr(self):
        """
        Start QR generation in background thread.
        """
        if not HAS_QRCODE:
            self.qr_status.setText(self.tr_text("qr_requires"))
            return
        val = self.qr_input.text().strip()
        if not val:
            return
        try:
            # disable button while generating
            self.gen_qr_btn.setEnabled(False)
            self.qr_status.setText("Generating...")
            self.qr_thread = QRThread(val, box_size=6, border=2)
            self.qr_thread.finished.connect(self._on_qr_finished)
            self.qr_thread.error.connect(self._on_qr_error)
            self.qr_thread.start()
        except Exception as e:
            self.qr_status.setText(f"{self.tr_text('error')}: {str(e)}")
            self.gen_qr_btn.setEnabled(True)

    def _on_qr_finished(self, img_bytes: bytes):
        try:
            self._last_qr_image_bytes = img_bytes
            qimg = QImage.fromData(self._last_qr_image_bytes)
            pix = QPixmap.fromImage(qimg)
            pix = pix.scaled(self.qr_label.width(), self.qr_label.height(), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.qr_label.setPixmap(pix)
            self.qr_status.setText("OK")
        except Exception as e:
            self.qr_status.setText(f"{self.tr_text('error')}: {str(e)}")
            self._last_qr_image_bytes = None
        finally:
            self.gen_qr_btn.setEnabled(True)

    def _on_qr_error(self, message: str):
        self.qr_status.setText(f"{self.tr_text('error')}: {message}")
        self._last_qr_image_bytes = None
        self.gen_qr_btn.setEnabled(True)

    def save_qr_png(self):
        if not self._last_qr_image_bytes:
            self.qr_status.setText("No QR to save")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save QR", "", "PNG Files (*.png);;All Files (*)")
        if not filename:
            return
        try:
            # ensure directory exists
            dirpath = os.path.dirname(filename)
            if dirpath and not os.path.exists(dirpath):
                os.makedirs(dirpath, exist_ok=True)
            with open(filename, "wb") as f:
                f.write(self._last_qr_image_bytes)
            self.qr_status.setText(self.tr_text("save_qr_png") + ": OK")
        except Exception as e:
            self.qr_status.setText(f"{self.tr_text('error')}: {str(e)}")

    # ---------------------------
    # Color methods
    # ---------------------------
    def pick_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.color_preview.setStyleSheet(f"background-color: {color.name()}; border-radius: 4px;")
            self.hex_input.setText(color.name())
            self.convert_hex()

    def convert_hex(self):
        """
        Validate hex like #RRGGBB or RRGGBB (case-insensitive).
        """
        hex_color = self.hex_input.text().strip()
        if not hex_color:
            self.color_result.setText("Empty")
            return
        # normalize
        if hex_color.startswith("#"):
            candidate = hex_color[1:]
        else:
            candidate = hex_color
        if not re.fullmatch(r"[0-9A-Fa-f]{6}", candidate):
            self.color_result.setText("Invalid HEX color format (use #RRGGBB)")
            return
        try:
            normalized = "#" + candidate.lower()
            color = QColor(normalized)
            if color.isValid():
                r, g, b = color.red(), color.green(), color.blue()
                self.rgb_input.setText(f"{r}, {g}, {b}")
                h, l, s = colorsys.rgb_to_hls(r / 255.0, g / 255.0, b / 255.0)
                h_deg = round(h * 360, 2)
                s_pct = round(s * 100, 2)
                l_pct = round(l * 100, 2)
                self.hsl_output.setText(f"{h_deg}°, {s_pct}%, {l_pct}%")
                self.color_result.setText(f"HEX: {color.name()}, RGB: {r},{g},{b}")
                self.color_preview.setStyleSheet(f"background-color: {color.name()}; border-radius: 4px;")
            else:
                self.color_result.setText("Invalid HEX color")
        except Exception as e:
            self.color_result.setText(f"{self.tr_text('error')}: {str(e)}")

    def convert_rgb(self):
        rgb_text = self.rgb_input.text().strip()
        try:
            parts = [int(p.strip()) for p in rgb_text.split(',')]
            if len(parts) != 3:
                self.color_result.setText("Need exactly 3 values (R,G,B)")
                return
            r, g, b = parts
            color = QColor(r, g, b)
            if color.isValid():
                self.hex_input.setText(color.name())
                h, l, s = colorsys.rgb_to_hls(r / 255.0, g / 255.0, b / 255.0)
                h_deg = round(h * 360, 2)
                s_pct = round(s * 100, 2)
                l_pct = round(l * 100, 2)
                self.hsl_output.setText(f"{h_deg}°, {s_pct}%, {l_pct}%")
                self.color_result.setText(f"HEX: {color.name()}, RGB: {r},{g},{b}")
                self.color_preview.setStyleSheet(f"background-color: {color.name()}; border-radius: 4px;")
            else:
                self.color_result.setText("Invalid RGB values (0-255)")
        except Exception as e:
            self.color_result.setText(f"{self.tr_text('error')}: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DevUtilityPro()
    window.show()
    sys.exit(app.exec())
