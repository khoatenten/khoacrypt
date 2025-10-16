import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinterdnd2 import DND_FILES, TkinterDnD
import os
import hashlib
import threading
import math
import json
import time 

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# =================================================================
# TỪ ĐIỂN DỊCH NGÔN NGỮ (Đã thêm key trung lập cho Algorithm)
# =================================================================
SETTINGS_FILE = "khoacrypt_settings.json"
LANGUAGES = {
    "vi": {
        "title": "KhoaCrypt Pro - Bộ Công Cụ Mã Hóa", "author_info": "KhoaCrypt Pro | Tác giả: Phan Phạm Vũ Khoa | v1.0",
        "tab_main": "Mã Hóa / Giải Mã", "tab_settings": "Cài đặt",
        "input_frame": "1. Đầu vào & Thông tin", "output_frame": "2. Đầu ra",
        "options_frame": "3. Tùy chọn Mã Hóa", 
        "input_file_btn": "Chọn File", "input_folder_btn": "Chọn Thư mục",
        "output_dir_label": "Thư mục lưu:", "output_filename_label": "Tên file (hoặc tiền tố cho thư mục):", "output_ext_label": "Đuôi file mã hóa:",
        "size_label": "Dung lượng:", "md5_label": "Mã Hash (MD5):", "hash_label": "Mã Hash (SHA-256):", "algo_label": "Thuật toán:",
        "delete_check": "Xóa file gốc sau khi mã hóa thành công", "encrypt_btn": "🔒 MÃ HÓA", "decrypt_btn": "🔑 GIẢI MÃ",
        "status_ready": "Sẵn sàng", "pass_title": "Nhập Mật Khẩu", "pass_prompt": "Nhập mật khẩu:",
        "settings_lang_label": "Ngôn ngữ:", "status_hash_calc": "Đang tính toán mã hash...",
        "path_label_prefix": "Đường dẫn:", 
        "path_default": "Đường dẫn: Chưa có gì được chọn", "size_default": "Dung lượng: N/A", "hash_default": "Mã Hash (SHA-256):",
        "md5_default": "Mã Hash (MD5):", 
        "path_invalid": "Đường dẫn không hợp lệ", "file_placeholder": "(Tái tạo cấu trúc thư mục)",
        "error_input_path": "Lỗi: Vui lòng chọn một file hoặc thư mục đầu vào hợp lệ.",
        "error_output_path": "Lỗi: Vui lòng chọn một thư mục lưu hợp lệ.",
        "message_encryption_canceled": "Đã hủy mã hóa.", "message_decryption_canceled": "Đã hủy giải mã.",
        "complete_encryption": "Mã hóa hoàn tất! File đã được lưu tại:", "complete_decryption": "Giải mã hoàn tất ({success_count}/{total_processed} file).",
        "fail_decryption": "Giải mã thất bại. Vui lòng kiểm tra lại mật khẩu hoặc file.",
        "error_unknown_algo": "Lỗi: Thuật toán không xác định hoặc file bị hỏng.",
        "key_strength_label": "Độ phức tạp khóa:", "key_strength_fast": "Nhanh (100k lần)", "key_strength_rec": "Khuyên dùng (480k lần)", "key_strength_max": "Tối đa (600k lần)",
        "algo_aes_gcm": "AES-256-GCM (Khuyên dùng)", # <-- KEY MỚI
        "algo_chacha20": "ChaCha20-Poly1305 (Nhanh)", # <-- KEY MỚI
        "algo_aes_cbc": "AES-256-CBC + HMAC", # <-- KEY MỚI
        "toggle_light": "☀️ Sáng", "toggle_dark": "🌙 Tối", "copy_btn": "📋 Sao chép", "copy_hash_status": "Đã sao chép SHA-256 Hash: {hash_prefix}...", "copy_hash_fail": "Không có mã hash hợp lệ để sao chép."
    },
    "en": {
        "title": "KhoaCrypt Pro - Encryption Toolkit", "author_info": "KhoaCrypt Pro | Author: Phan Pham Vu Khoa | v1.0",
        "tab_main": "Encrypt / Decrypt", "tab_settings": "Settings",
        "input_frame": "1. Input & Information", "output_frame": "2. Output",
        "options_frame": "3. Encryption Options", 
        "input_file_btn": "Select File", "input_folder_btn": "Select Folder",
        "output_dir_label": "Destination:", "output_filename_label": "Filename (or folder prefix):", "output_ext_label": "Encrypted extension:",
        "size_label": "Size:", "md5_label": "Hash (MD5):", "hash_label": "Hash (SHA-256):", "algo_label": "Algorithm:",
        "delete_check": "Delete original file after successful encryption", "encrypt_btn": "🔒 ENCRYPT", "decrypt_btn": "🔑 DECRYPT",
        "status_ready": "Ready", "pass_title": "Enter Password", "pass_prompt": "Enter password:",
        "settings_lang_label": "Language:", "status_hash_calc": "Calculating hash...",
        "path_label_prefix": "Path:",
        "path_default": "Path: Nothing selected", "size_default": "Size: N/A", "hash_default": "Hash (SHA-256):",
        "md5_default": "Hash (MD5):",
        "path_invalid": "Invalid path", "file_placeholder": "(Recreates folder structure)",
        "error_input_path": "Error: Please select a valid input file or folder.",
        "error_output_path": "Error: Please select a valid destination folder.",
        "message_encryption_canceled": "Encryption canceled.", "message_decryption_canceled": "Decryption canceled.",
        "complete_encryption": "Encryption complete! File saved at:", "complete_decryption": "Decryption complete ({success_count}/{total_processed} files).",
        "fail_decryption": "Decryption failed. Please check password or file.",
        "error_unknown_algo": "Error: Unknown algorithm or corrupted file.",
        "key_strength_label": "Key derivation strength:", "key_strength_fast": "Fast (100k iter.)", "key_strength_rec": "Recommended (480k iter.)", "key_strength_max": "Maximum (600k iter.)",
        "algo_aes_gcm": "AES-256-GCM (Recommended)", # <-- KEY MỚI
        "algo_chacha20": "ChaCha20-Poly1305 (Fast)", # <-- KEY MỚI
        "algo_aes_cbc": "AES-256-CBC + HMAC", # <-- KEY MỚI
        "toggle_light": "☀️ Light", "toggle_dark": "🌙 Dark", "copy_btn": "📋 Copy", "copy_hash_status": "Copied SHA-256 Hash: {hash_prefix}...", "copy_hash_fail": "No valid hash available to copy."
    }
}
KEY_ITERATIONS = {
    "Nhanh (100k lần)": 100000, "Khuyên dùng (480k lần)": 480000, "Tối đa (600k lần)": 600000,
    "Fast (100k iter.)": 100000, "Recommended (480k iter.)": 480000, "Maximum (600k iter.)": 600000
}

# Sử dụng KEY TRUNG LẬP cho cả Algorithm và Key Strength
ALGO_KEYS = ["algo_aes_gcm", "algo_chacha20", "algo_aes_cbc"] 
KEY_STRENGTH_KEYS = ["key_strength_fast", "key_strength_rec", "key_strength_max"]

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title="Enter Password"):
        super().__init__(parent)
        self.title(title); self.transient(parent); self.result = None; self.parent = parent
        self.resizable(False, False); self.grab_set()
        self.body(); self.buttonbox(); self.wait_window(self)
    def body(self):
        lang = self.parent.current_language; frame = ttk.Frame(self, padding="15"); frame.pack(padx=10, pady=10)
        ttk.Label(frame, text=LANGUAGES[lang]["pass_prompt"]).grid(row=0, column=0, sticky="w", pady=5)
        self.entry = ttk.Entry(frame, show='*', width=30, bootstyle="primary"); self.entry.grid(row=0, column=1, padx=5, pady=5); self.entry.focus_set()
        self.bind("<Return>", self.ok)
    def buttonbox(self):
        box = ttk.Frame(self)
        ttk.Button(box, text="OK", width=10, command=self.ok, bootstyle="success").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(box, text="Cancel", width=10, command=self.cancel, bootstyle="danger-outline").pack(side=tk.LEFT, padx=5, pady=5)
        box.pack()
    def ok(self, event=None): self.result = self.entry.get(); self.destroy()
    def cancel(self, event=None): self.result = None; self.destroy()

class KhoaCryptApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.current_language = "en"; # MẶC ĐỊNH LÀ TIẾNG ANH
        self.key_strength_index = 1; self.current_theme = 'darkly'
        self.style = ttk.Style(theme='darkly')
        self.load_settings()
        # Key luôn là tiếng Anh nhưng giá trị được dịch
        self.ALGORITHMS = {
            LANGUAGES['en']['algo_aes_gcm']: 1, 
            LANGUAGES['en']['algo_chacha20']: 2, 
            LANGUAGES['en']['algo_aes_cbc']: 3
        }
        self.file_path = None
        self.last_calculated_hash = {"MD5": "N/A", "SHA-256": "N/A"} # Lưu trữ Hash
        try: self.iconbitmap("icon.ico")
        except tk.TclError: print("Không tìm thấy file icon.ico, bỏ qua.")
        self.setup_widgets()
        self.post_setup_apply_settings()
        self.update_idletasks(); width = self.winfo_reqwidth(); height = self.winfo_reqheight()
        self.geometry(f"{width}x{height}"); self.resizable(False, False)
        self.dnd_bind('<<Drop>>', self.handle_drop) 

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f: settings = json.load(f)
                if 'language' in settings and settings['language'] in LANGUAGES: self.current_language = settings['language']
                if 'theme' in settings and settings['theme'] in ['darkly', 'flatly']: self.current_theme = settings['theme']; self.style.theme_use(self.current_theme)
                if 'key_strength_index' in settings and 0 <= settings['key_strength_index'] <= 2: self.key_strength_index = settings['key_strength_index']
            except Exception: pass

    def save_settings(self):
        settings = {'language': self.current_language, 'theme': self.current_theme, 'key_strength_index': self.key_strength_combo.current()}
        try:
            with open(SETTINGS_FILE, 'w') as f: json.dump(settings, f, indent=4)
        except Exception: pass

    def post_setup_apply_settings(self):
        self.update_translations()
        # Đảm bảo ComboBox Key Strength được đặt lại đúng
        if self.key_strength_index is not None: 
             try:
                 self.key_strength_combo.current(self.key_strength_index)
             except Exception:
                 self.key_strength_combo.current(1)

        self.toggle_btn.config(text=LANGUAGES[self.current_language]["toggle_" + ('dark' if self.current_theme == 'flatly' else 'light')])

    def update_translations(self):
        lang = self.current_language
        self.title(LANGUAGES[lang]["title"]); self.version_label.config(text=LANGUAGES[lang]["author_info"])
        self.notebook.tab(0, text=LANGUAGES[lang]["tab_main"]); self.notebook.tab(1, text=LANGUAGES[lang]["tab_settings"])
        self.input_info_frame.config(text=LANGUAGES[lang]["input_frame"]); self.output_frame.config(text=LANGUAGES[lang]["output_frame"])
        self.options_frame.config(text=LANGUAGES[lang]["options_frame"]); self.path_label.config(text=LANGUAGES[lang]["path_default"])
        self.size_label.config(text=LANGUAGES[lang]["size_default"]); self.md5_label.config(text=LANGUAGES[lang]["md5_default"]); self.hash_label.config(text=LANGUAGES[lang]["hash_default"])
        self.input_file_btn.config(text=LANGUAGES[lang]["input_file_btn"]); self.input_folder_btn.config(text=LANGUAGES[lang]["input_folder_btn"])
        self.output_dir_label.config(text=LANGUAGES[lang]["output_dir_label"]); self.output_filename_label.config(text=LANGUAGES[lang]["output_filename_label"])
        self.output_ext_label.config(text=LANGUAGES[lang]["output_ext_label"]); self.algo_label.config(text=LANGUAGES[lang]["algo_label"])
        self.delete_check.config(text=LANGUAGES[lang]["delete_check"]); self.encrypt_btn.config(text=LANGUAGES[lang]["encrypt_btn"])
        self.decrypt_btn.config(text=LANGUAGES[lang]["decrypt_btn"]); self.status_bar.config(text=LANGUAGES[lang]["status_ready"])
        self.settings_lang_label.config(text=LANGUAGES[lang]["settings_lang_label"]); self.lang_settings_frame.config(text=LANGUAGES[lang]["tab_settings"])
        self.key_strength_label.config(text=LANGUAGES[lang]["key_strength_label"])
        self.copy_btn.config(text=LANGUAGES[lang]["copy_btn"])
        
        # Cập nhật Combobox Thuật toán: Sử dụng ALGO_KEYS trung lập
        new_algo_values = [LANGUAGES[lang][key] for key in ALGO_KEYS]
        self.algo_combo.config(values=new_algo_values)
        self.algo_combo.current(0) # Giữ lựa chọn mặc định

        # Cập nhật Combobox Độ phức tạp khóa: Sử dụng KEY_STRENGTH_KEYS trung lập
        current_index = self.key_strength_combo.current() 
        new_key_values = [LANGUAGES[lang][k] for k in KEY_STRENGTH_KEYS]
        self.key_strength_combo.config(values=new_key_values)
        try: self.key_strength_combo.current(current_index if current_index >= 0 else 1)
        except Exception: self.key_strength_combo.current(1)
        
        self.toggle_btn.config(text=LANGUAGES[lang]["toggle_" + ('dark' if self.current_theme == 'flatly' else 'light')])
        
        # Cập nhật self.ALGORITHMS để phản ánh tên thuật toán mới sau khi dịch
        self.ALGORITHMS = {LANGUAGES[lang][key]: val for key, val in zip(ALGO_KEYS, [1, 2, 3])}


    def set_language(self, language_code): 
        self.current_language = language_code
        self.update_translations()
        self.save_settings()

    def toggle_theme(self):
        self.current_theme = 'flatly' if self.current_theme == 'darkly' else 'darkly'
        self.style.theme_use(self.current_theme); self.update_translations(); self.save_settings()

    def on_key_strength_change(self, event): self.key_strength_index = self.key_strength_combo.current(); self.save_settings()

    def select_path_dialog(self, entry_widget, is_file=True):
        path = filedialog.askopenfilename() if is_file else filedialog.askdirectory()
        if path: entry_widget.delete(0, END); entry_widget.insert(0, path)
        if entry_widget == self.path_entry: self.update_file_info(path)

    def select_output_dir(self):
        path = filedialog.askdirectory()
        if path: self.output_dir_entry.delete(0, END); self.output_dir_entry.insert(0, path)

    def on_path_entry_change(self, event):
        path = self.path_entry.get()
        if os.path.exists(path): self.update_file_info(path)
        else: self.update_file_info(None)

    def setup_widgets(self):
        top_bar = ttk.Frame(self, padding=5); top_bar.pack(fill=X, side=TOP)
        self.toggle_btn = ttk.Button(top_bar, bootstyle="secondary-outline", command=self.toggle_theme, width=15); self.toggle_btn.pack(side=RIGHT, padx=10, pady=5)
        self.version_label = ttk.Label(top_bar, bootstyle="secondary", anchor=W, font=("Helvetica", 10, "bold")); self.version_label.pack(side=LEFT, padx=10, pady=5)
        
        self.notebook = ttk.Notebook(self); self.notebook.pack(fill=BOTH, expand=YES, padx=20, pady=10)
        main_tab = ttk.Frame(self.notebook, padding="20"); settings_tab = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(main_tab, text="Encrypt / Decrypt", sticky="nsew"); self.notebook.add(settings_tab, text="Settings", sticky="nsew")

        # --- MAIN TAB ---
        self.input_info_frame = ttk.LabelFrame(main_tab, padding="15"); self.input_info_frame.pack(fill=X, pady=10)
        input_bar_frame = ttk.Frame(self.input_info_frame); input_bar_frame.pack(fill=X, pady=(0, 10)); input_bar_frame.columnconfigure(0, weight=1)
        self.path_entry = ttk.Entry(input_bar_frame, bootstyle="primary", font=("Helvetica", 10)); self.path_entry.grid(row=0, column=0, padx=(5, 0), sticky="ew"); self.path_entry.bind('<KeyRelease>', self.on_path_entry_change)
        browse_frame = ttk.Frame(input_bar_frame); browse_frame.grid(row=0, column=1, padx=(5, 0), sticky="e")
        self.input_file_btn = ttk.Button(browse_frame, command=lambda: self.select_path_dialog(self.path_entry, is_file=True)); self.input_file_btn.pack(side=LEFT, padx=2)
        self.input_folder_btn = ttk.Button(browse_frame, command=lambda: self.select_path_dialog(self.path_entry, is_file=False)); self.input_folder_btn.pack(side=LEFT, padx=2)
        
        # Hash Info Widgets
        hash_frame = ttk.Frame(self.input_info_frame)
        hash_frame.pack(fill=X, pady=5)
        hash_frame.columnconfigure(0, weight=1)
        
        self.path_label = ttk.Label(self.input_info_frame, wraplength=600); self.path_label.pack(fill=X)
        self.size_label = ttk.Label(self.input_info_frame); self.size_label.pack(fill=X, pady=2)
        
        # MD5 Hash Label
        self.md5_label = ttk.Label(hash_frame, wraplength=500, font=("Courier", 10)); self.md5_label.grid(row=0, column=0, padx=5, sticky="w")
        
        # SHA-256 Hash Label
        self.hash_label = ttk.Label(hash_frame, wraplength=500, font=("Courier", 10)); self.hash_label.grid(row=1, column=0, padx=5, pady=2, sticky="w")
        
        # Copy Button
        self.copy_btn = ttk.Button(hash_frame, command=self.copy_hash_to_clipboard, width=10, bootstyle="info-outline")
        self.copy_btn.grid(row=0, column=1, rowspan=2, padx=5, sticky="e")


        self.output_frame = ttk.LabelFrame(main_tab, padding="15"); self.output_frame.pack(fill=X, pady=10)
        self.output_dir_label = ttk.Label(self.output_frame); self.output_dir_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        output_dir_entry_frame = ttk.Frame(self.output_frame); output_dir_entry_frame.grid(row=1, column=0, columnspan=3, padx=5, sticky="ew"); output_dir_entry_frame.columnconfigure(0, weight=1)
        self.output_dir_entry = ttk.Entry(output_dir_entry_frame, bootstyle="primary", font=("Helvetica", 10)); self.output_dir_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(output_dir_entry_frame, text="...", bootstyle="info-outline", command=self.select_output_dir, width=3).grid(row=0, column=1, padx=(5, 0), sticky="e")
        name_ext_frame = ttk.Frame(self.output_frame, padding=(0, 5)); name_ext_frame.grid(row=2, column=0, columnspan=3, sticky="ew"); name_ext_frame.columnconfigure(0, weight=1)
        self.output_filename_label = ttk.Label(name_ext_frame); self.output_filename_label.grid(row=0, column=0, padx=5, sticky="w")
        self.output_ext_label = ttk.Label(name_ext_frame, width=15); self.output_ext_label.grid(row=0, column=1, padx=5, sticky="w")
        self.filename_entry = ttk.Entry(name_ext_frame, bootstyle="primary"); self.filename_entry.grid(row=1, column=0, padx=5, sticky="ew")
        self.ext_entry = ttk.Entry(name_ext_frame, bootstyle="primary", width=15); self.ext_entry.grid(row=1, column=1, padx=5, sticky="ew"); self.ext_entry.insert(0, ".khoacrypt")
        
        self.options_frame = ttk.LabelFrame(main_tab, padding="15"); self.options_frame.pack(fill=X, pady=10); self.options_frame.columnconfigure(1, weight=1)
        self.algo_label = ttk.Label(self.options_frame); self.algo_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        # Khởi tạo Combobox Thuật toán
        initial_algo_values = [LANGUAGES['en'][k] for k in ALGO_KEYS]
        self.algo_combo = ttk.Combobox(self.options_frame, values=initial_algo_values, state="readonly", bootstyle="primary"); 
        self.algo_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew"); self.algo_combo.current(0)
        self.key_strength_label = ttk.Label(self.options_frame); self.key_strength_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        # Khởi tạo Combobox Độ phức tạp khóa
        initial_key_values = [LANGUAGES['en'][k] for k in KEY_STRENGTH_KEYS]
        self.key_strength_combo = ttk.Combobox(self.options_frame, values=initial_key_values, state="readonly", bootstyle="primary"); 
        self.key_strength_combo.grid(row=1, column=1, padx=5, pady=5, sticky="ew"); self.key_strength_combo.current(1); self.key_strength_combo.bind("<<ComboboxSelected>>", self.on_key_strength_change)
        check_frame = ttk.Frame(self.options_frame); check_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="w")
        self.delete_original_var = tk.BooleanVar()
        self.delete_check = ttk.Checkbutton(check_frame, variable=self.delete_original_var, bootstyle="danger-round-toggle"); self.delete_check.pack(side=tk.LEFT, padx=10)
        
        action_frame = ttk.Frame(main_tab); action_frame.pack(fill=X, pady=20); action_frame.columnconfigure((0, 1), weight=1)
        self.encrypt_btn = ttk.Button(action_frame, command=self.start_encryption_thread, padding=(15, 20)); self.encrypt_btn.grid(row=0, column=0, padx=10, sticky="ew")
        self.decrypt_btn = ttk.Button(action_frame, command=self.start_decryption_thread, padding=(15, 20)); self.decrypt_btn.grid(row=0, column=1, padx=10, sticky="ew")
        self.progress = ttk.Progressbar(main_tab, bootstyle="success-striped", length=100); self.progress.pack(fill=X, pady=10)

        # --- SETTINGS TAB ---
        self.lang_settings_frame = ttk.LabelFrame(settings_tab, padding=15); self.lang_settings_frame.pack(fill=X, pady=10)
        self.settings_lang_label = ttk.Label(self.lang_settings_frame); self.settings_lang_label.pack(side=LEFT, padx=5, pady=5)
        lang_options = ["Tiếng Việt (vi)", "English (en)"]
        self.lang_combo = ttk.Combobox(self.lang_settings_frame, values=lang_options, state="readonly", bootstyle="primary", width=20); 
        self.lang_combo.pack(side=LEFT, padx=5, pady=5)
        self.lang_combo.bind("<<ComboboxSelected>>", self.on_language_change)
        
        # Đặt giá trị mặc định cho Lang Combo
        if self.current_language == "en":
            self.lang_combo.current(1)
        else:
            self.lang_combo.current(0)
        
        # --- STATUS BAR ---
        self.status_bar = ttk.Label(self, bootstyle="inverse-secondary", padding=5, anchor=W); self.status_bar.pack(side=BOTTOM, fill=X)

    def on_language_change(self, event):
        selected_text = self.lang_combo.get(); lang_code = selected_text[-3:-1]; self.set_language(lang_code)

    def copy_hash_to_clipboard(self):
        hash_to_copy = self.last_calculated_hash.get("SHA-256")
        lang = self.current_language
        if hash_to_copy and hash_to_copy != "N/A" and not hash_to_copy.startswith("Lỗi") and not hash_to_copy.startswith("Error"):
            self.clipboard_clear()
            self.clipboard_append(hash_to_copy)
            hash_prefix = hash_to_copy[:10]
            self.status_bar.config(text=LANGUAGES[lang]["copy_hash_status"].format(hash_prefix=hash_prefix))
        else:
             self.status_bar.config(text=LANGUAGES[lang]["copy_hash_fail"])

    def start_task_in_thread(self, target_func, *args):
        for btn in [self.encrypt_btn, self.decrypt_btn]: btn.config(state="disabled")
        self.progress.config(mode='indeterminate'); self.progress.start(10)
        thread = threading.Thread(target=target_func, args=args); thread.daemon = True; thread.start()

    def update_progress(self, current_bytes, total_bytes, status_prefix):
        # Chức năng này chạy trên main thread (do được gọi bằng self.after)
        if total_bytes > 0:
            self.progress.config(mode='determinate'); self.progress.stop()
            percentage = (current_bytes / total_bytes) * 100; self.progress['value'] = percentage
            status_text = f"{status_prefix} ({percentage:.1f}%) ({self.format_bytes(current_bytes)} / {self.format_bytes(total_bytes)})"
            self.status_bar.config(text=status_text)
        else: self.status_bar.config(text=status_prefix)

    def task_done(self, final_message, success=True):
        self.progress.stop(); self.progress.config(mode='determinate'); self.progress['value'] = 100 if success else 0
        for btn in [self.encrypt_btn, self.decrypt_btn]: btn.config(state="normal")
        
        if success:
            self.after(100, lambda: messagebox.showinfo(LANGUAGES[self.current_language]["tab_main"], final_message))
        else:
            self.after(100, lambda: messagebox.showerror(LANGUAGES[self.current_language]["tab_main"], final_message))
            
        self.progress['value'] = 0; self.status_bar.config(text=LANGUAGES[self.current_language]["status_ready"])

    def start_encryption_thread(self):
        path = self.path_entry.get(); output_dir = self.output_dir_entry.get()
        if not (path and os.path.exists(path)): messagebox.showwarning(LANGUAGES[self.current_language]["tab_main"], LANGUAGES[self.current_language]["error_input_path"]); return
        if not (output_dir and os.path.isdir(output_dir)): messagebox.showwarning(LANGUAGES[self.current_language]["tab_main"], LANGUAGES[self.current_language]["error_output_path"]); return
        self.file_path = path; self.start_task_in_thread(self.process_encryption)
        
    def start_decryption_thread(self):
        path = self.path_entry.get(); output_dir = self.output_dir_entry.get()
        if not (path and os.path.exists(path)): messagebox.showwarning(LANGUAGES[self.current_language]["tab_main"], LANGUAGES[self.current_language]["error_input_path"]); return
        if not (output_dir and os.path.isdir(output_dir)): messagebox.showwarning(LANGUAGES[self.current_language]["tab_main"], LANGUAGES[self.current_language]["error_output_path"]); return
        self.file_path = path; self.start_task_in_thread(self.process_decryption)

    def process_encryption(self):
        output_dir = self.output_dir_entry.get(); output_filename = self.filename_entry.get().strip()
        password = self.get_password(LANGUAGES[self.current_language]["pass_title"])
        if not password: self.after(0, self.task_done, LANGUAGES[self.current_language]["message_encryption_canceled"], success=False); return
        algo_name = self.algo_combo.get(); extension = self.ext_entry.get()
        if not extension.startswith('.'): extension = '.' + extension
        delete_original = self.delete_original_var.get(); 
        
        # Lấy giá trị iterations từ key tiếng Anh/Việt tương ứng
        iterations_key = self.key_strength_combo.get()
        iterations = KEY_ITERATIONS.get(iterations_key, 480000)
        
        try:
            if os.path.isfile(self.file_path):
                self.encrypt_file(self.file_path, password, algo_name, extension, delete_original, output_dir=output_dir, output_filename=output_filename, iterations=iterations)
            elif os.path.isdir(self.file_path):
                prefix = output_filename if output_filename and LANGUAGES[self.current_language]["file_placeholder"] not in output_filename else ""
                files_to_process = [os.path.join(r, f) for r, _, fs in os.walk(self.file_path) for f in fs]; total = len(files_to_process)
                for i, f in enumerate(files_to_process):
                    relative_path = os.path.relpath(f, self.file_path); new_output_dir = os.path.join(output_dir, os.path.dirname(relative_path))
                    os.makedirs(new_output_dir, exist_ok=True)
                    self.after(0, self.update_progress, i, total, f"{LANGUAGES[self.current_language]['encrypt_btn']}ing Folder... ({i+1}/{total})")
                    current_output_filename = prefix + os.path.basename(f)
                    self.encrypt_file(f, password, algo_name, extension, delete_original, update_ui=False, output_dir=new_output_dir, output_filename=current_output_filename, iterations=iterations)
            self.after(0, self.task_done, f"{LANGUAGES[self.current_language]['complete_encryption']} {output_dir}")
        except Exception as e: self.after(0, self.task_done, f"{LANGUAGES[self.current_language]['error_unknown_algo']}: {e}", success=False)

    def encrypt_file(self, file_path, password, algo_name, extension, delete_original, update_ui=True, output_dir=None, output_filename=None, iterations=480000):
        try:
            total_size = os.path.getsize(file_path); CHUNK_SIZE = 16 * 1024 * 1024
            with open(file_path, 'rb') as f_in:
                data_chunks = []; bytes_processed = 0
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk: break
                    data_chunks.append(chunk); bytes_processed += len(chunk)
                    if update_ui: self.after(0, self.update_progress, bytes_processed, total_size, f"{LANGUAGES[self.current_language]['encrypt_btn']}ing...")
                data = b''.join(data_chunks)
            
            # Đảm bảo lấy ID thuật toán từ tên đã được dịch
            algo_id = self.ALGORITHMS.get(algo_name, 0)
            if algo_id == 0: raise ValueError(LANGUAGES[self.current_language]["error_unknown_algo"])
            
            salt = os.urandom(16); payload = None
            if algo_id in [1, 2]: # AEAD
                key = self.derive_keys(password, salt, 32, iterations=iterations); nonce = os.urandom(12)
                cipher_aead = AESGCM(key) if algo_id == 1 else ChaCha20Poly1305(key)
                ciphertext = cipher_aead.encrypt(nonce, data, None)
                payload = algo_id.to_bytes(1, 'big') + salt + nonce + ciphertext
            elif algo_id == 3: # CBC + HMAC
                key_length = 32; derived_material = self.derive_keys(password, salt, key_length + 32, iterations=iterations)
                enc_key, hmac_key = derived_material[:key_length], derived_material[key_length:]
                iv = os.urandom(16); cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
                encryptor = cipher.encryptor(); padder = padding.PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(data) + padder.finalize(); ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                h = hmac.HMAC(hmac_key, hashes.SHA256()); h.update(ciphertext); tag = h.finalize()
                payload = algo_id.to_bytes(1, 'big') + salt + iv + tag + ciphertext
            
            base_name = output_filename if output_filename else os.path.basename(file_path)
            output_file_path = os.path.join(output_dir, base_name + extension)
            with open(output_file_path, 'wb') as f_out: f_out.write(payload)
            if delete_original: os.remove(file_path)
            return True
        except Exception as e: 
            if update_ui: self.after(0, messagebox.showerror, LANGUAGES[self.current_language]["tab_main"], f"Encryption error for {os.path.basename(file_path)}: {e}")
            return False

    def process_decryption(self):
        output_dir = self.output_dir_entry.get()
        password = self.get_password(LANGUAGES[self.current_language]["pass_title"])
        
        if not password: 
            self.after(0, self.task_done, LANGUAGES[self.current_language]["message_decryption_canceled"], success=False)
            return

        success_count = 0; total_processed = 0; 
        
        # Lấy giá trị iterations từ key tiếng Anh/Việt tương ứng
        iterations_key = self.key_strength_combo.get()
        iterations = KEY_ITERATIONS.get(iterations_key, 480000)
        
        try:
            if os.path.isfile(self.file_path):
                if self.decrypt_file(self.file_path, password, output_dir=output_dir, iterations=iterations, update_ui=True): 
                    success_count += 1
                total_processed = 1
                
            elif os.path.isdir(self.file_path):
                extension = self.ext_entry.get()
                if not extension.startswith('.'): extension = '.' + extension
                files_to_process = [os.path.join(r, f) for r, _, fs in os.walk(self.file_path) for f in fs if f.endswith(extension)]
                total_processed = len(files_to_process)
                for i, f in enumerate(files_to_process):
                    relative_path = os.path.relpath(f, self.file_path); new_output_dir = os.path.join(output_dir, os.path.dirname(relative_path))
                    os.makedirs(new_output_dir, exist_ok=True)
                    self.after(0, self.update_progress, i, total_processed, f"{LANGUAGES[self.current_language]['decrypt_btn']}ing Folder... ({i+1}/{total_processed})")
                    if self.decrypt_file(f, password, update_ui=False, output_dir=new_output_dir, iterations=iterations): 
                        success_count += 1
            
            if success_count > 0:
                final_message = LANGUAGES[self.current_language]["complete_decryption"].format(success_count=success_count, total_processed=total_processed)
                self.after(0, self.task_done, final_message)
            else: 
                # Không có file nào được giải mã thành công (bao gồm cả sai mật khẩu)
                self.after(0, self.task_done, LANGUAGES[self.current_language]["fail_decryption"], success=False)
                
        except Exception as e: 
            self.after(0, self.task_done, f"{LANGUAGES[self.current_language]['error_unknown_algo']}: {e}", success=False)


    def decrypt_file(self, file_path, password, update_ui=True, output_dir=None, iterations=480000):
        result = False
        try:
            total_size = os.path.getsize(file_path); CHUNK_SIZE = 16 * 1024 * 1024
            with open(file_path, 'rb') as f_in:
                algo_id_bytes = f_in.read(1); salt = f_in.read(16); bytes_processed = 17
                if update_ui: self.after(0, self.update_progress, bytes_processed, total_size, f"{LANGUAGES[self.current_language]['decrypt_btn']}ing...")
                remaining_chunks = []
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk: break
                    remaining_chunks.append(chunk); bytes_processed += len(chunk)
                    if update_ui: self.after(0, self.update_progress, bytes_processed, total_size, f"{LANGUAGES[self.current_language]['decrypt_btn']}ing...")
                remaining_data = b''.join(remaining_chunks)
            
            algo_id = int.from_bytes(algo_id_bytes, 'big'); decrypted_data = None
            if algo_id in [1, 2]: # AEAD
                nonce, ciphertext = remaining_data[:12], remaining_data[12:]
                key = self.derive_keys(password, salt, 32, iterations=iterations)
                cipher_aead = AESGCM(key) if algo_id == 1 else ChaCha20Poly1305(key)
                decrypted_data = cipher_aead.decrypt(nonce, ciphertext, None)
            elif algo_id == 3: # CBC + HMAC
                key_length = 32; iv = remaining_data[:16]; stored_tag = remaining_data[16:48]; ciphertext = remaining_data[48:]
                derived_material = self.derive_keys(password, salt, key_length + 32, iterations=iterations)
                enc_key, hmac_key = derived_material[:key_length], derived_material[key_length:]
                h = hmac.HMAC(hmac_key, hashes.SHA256()); h.update(ciphertext); h.verify(stored_tag)
                cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv)); decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            else: raise ValueError(LANGUAGES[self.current_language]["error_unknown_algo"])
            
            original_base_name, _ = os.path.splitext(os.path.basename(file_path))
            output_path = os.path.join(output_dir, original_base_name)

            with open(output_path, 'wb') as f_out: f_out.write(decrypted_data)
            result = True 
        except (InvalidTag, ValueError) as e:
            # Lỗi giải mã do sai mật khẩu/file hỏng
            if update_ui:
                # Hiển thị lỗi nhưng không gọi task_done (để task_done ở process_decryption xử lý khôi phục nút)
                self.after(0, messagebox.showerror, LANGUAGES[self.current_language]["tab_main"], LANGUAGES[self.current_language]["fail_decryption"])
            result = False
        except Exception as e:
            # Bắt các lỗi I/O hoặc lỗi hệ thống khác.
            if update_ui:
                self.after(0, messagebox.showerror, LANGUAGES[self.current_language]["tab_main"], f"Error: {e}")
            result = False
        
        return result

    def format_bytes(self, size):
        if size == 0: return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB"); i = int(math.floor(math.log(size, 1024)))
        p = math.pow(1024, i); s = round(size / p, 2); return f"{s} {size_name[i]}"

    def update_file_info(self, path):
        self.file_path = path; lang = self.current_language
        self.last_calculated_hash = {"MD5": "N/A", "SHA-256": "N/A"} # Reset Hash

        if path and os.path.exists(path):
            self.path_label.config(text=f"{LANGUAGES[lang]['path_label_prefix']} {path}")
            if os.path.isfile(path):
                self.filename_entry.delete(0, END); base_filename = os.path.basename(path)
                current_ext = self.ext_entry.get()
                if base_filename.endswith(current_ext): base_filename = base_filename[:-len(current_ext)]
                self.filename_entry.insert(0, base_filename)
                try: file_size = os.path.getsize(path); self.size_label.config(text=f"{LANGUAGES[lang]['size_label']} {self.format_bytes(file_size)}")
                except Exception: self.size_label.config(text=f"{LANGUAGES[lang]['size_label']} Error")
                
                self.md5_label.config(text=LANGUAGES[lang]["md5_default"] + " N/A")
                self.hash_label.config(text=LANGUAGES[lang]["hash_default"] + " N/A")
                self.status_bar.config(text=LANGUAGES[lang]["status_hash_calc"])
                # Bắt đầu tính hash trong luồng nền
                threading.Thread(target=self.calculate_hash_threaded, args=(path,)).start()
            else: # Thư mục
                self.filename_entry.delete(0, END); self.filename_entry.insert(0, LANGUAGES[lang]["file_placeholder"])
                self.size_label.config(text=f"{LANGUAGES[lang]['size_label']} N/A ({LANGUAGES[lang]['input_folder_btn']})")
                self.md5_label.config(text=LANGUAGES[lang]["md5_default"] + " N/A")
                self.hash_label.config(text=LANGUAGES[lang]["hash_default"] + " N/A")
                self.status_bar.config(text=LANGUAGES[lang]["status_ready"])
        else: # Đường dẫn không hợp lệ hoặc rỗng
            self.path_label.config(text=LANGUAGES[lang]["path_invalid" if path else "path_default"]); self.size_label.config(text=LANGUAGES[lang]["size_default"])
            self.md5_label.config(text=LANGUAGES[lang]["md5_default"])
            self.hash_label.config(text=LANGUAGES[lang]["hash_default"])
            self.filename_entry.delete(0, END); self.status_bar.config(text=LANGUAGES[lang]["status_ready"])

    def update_hash_ui(self, hash_results):
        lang = self.current_language
        self.last_calculated_hash = hash_results # Lưu trữ hash để copy
        
        md5_text = hash_results["MD5"] if not hash_results["MD5"].startswith("Lỗi") and not hash_results["MD5"].startswith("Error") else "Error"
        sha256_text = hash_results["SHA-256"] if not hash_results["SHA-256"].startswith("Lỗi") and not hash_results["SHA-256"].startswith("Error") else "Error"
        
        self.md5_label.config(text=f"{LANGUAGES[lang]['md5_label']} {md5_text}")
        self.hash_label.config(text=f"{LANGUAGES[lang]['hash_label']} {sha256_text}")
        self.status_bar.config(text=LANGUAGES[lang]["status_ready"])

    def calculate_hash_threaded(self, file_path): 
        hashes = self.calculate_hash(file_path)
        self.after(0, self.update_hash_ui, hashes)

    def derive_keys(self, password, salt, key_length=32, iterations=480000):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=iterations); return kdf.derive(password.encode())
        
    def calculate_hash(self, file_path):
        md5 = hashlib.md5(); sha256 = hashlib.sha256(); CHUNK_SIZE = 16 * 1024 * 1024
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE): 
                    md5.update(chunk)
                    sha256.update(chunk)
            return {"MD5": md5.hexdigest(), "SHA-256": sha256.hexdigest()}
        except Exception as e: return {"MD5": f"Error: {e}", "SHA-256": f"Error: {e}"}
        
    def get_password(self, title): dialog = PasswordDialog(self, title=title); return dialog.result
        
    def handle_drop(self, event):
        path = event.data.strip('{}'); self.path_entry.delete(0, END)
        self.path_entry.insert(0, path); self.update_file_info(path)

if __name__ == "__main__":
    app = KhoaCryptApp()
    app.mainloop()
