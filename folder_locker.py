"""
Secure Folder Locker - FINAL STABLE VERSION (Ready for 2FA)
- Protects folders and individual files
- Items disappear into hidden vault
- Only accessible via GUI
- Progress bar during lock/unlock (no freezing)
- Settings: Change master password + change individual item password
- Force Remove for recovery
- Error logging
- Clean, responsive, modern UI
"""

import os
import sys
import json
import base64
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
import secrets
import threading
import time
import logging
import traceback

import customtkinter as ctk
from tkinter import messagebox, filedialog

# Cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Windows window monitoring
if sys.platform == "win32":
    import win32gui

# Theme (fixed dark - no switching to prevent freeze)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ========================= LOGGING =========================
logging.basicConfig(
    filename="locker_errors.log",
    level=logging.ERROR,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log_error(msg: str):
    logging.error(msg + "\n" + traceback.format_exc())

# ========================= CONFIG =========================
CONFIG_DIR = Path.home() / ".secure_folder_locker"
CONFIG_DIR.mkdir(exist_ok=True)
VAULT_DIR = CONFIG_DIR / "vaults"
VAULT_DIR.mkdir(exist_ok=True)

MASTER_FILE = CONFIG_DIR / "master.json"
ITEMS_FILE = CONFIG_DIR / "items.json"

PBKDF2_ITERATIONS = 120000
KEY_LENGTH = 32
SALT_LENGTH = 32

# ======================= PASSWORD DIALOG =========================
class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent=None, title="Password Required", prompt="Enter password:"):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x220")
        self.resizable(False, False)
        if parent:
            self.transient(parent)
            self.grab_set()
        self.attributes("-topmost", True)

        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 200
        y = (self.winfo_screenheight() // 2) - 110
        self.geometry(f"+{x}+{y}")

        ctk.CTkLabel(self, text=prompt, font=("Segoe UI", 16)).pack(pady=30)

        self.password_var = ctk.StringVar()
        self.entry = ctk.CTkEntry(
            self,
            textvariable=self.password_var,
            show="●",
            width=300,
            height=40,
            font=("Segoe UI", 14)
        )
        self.entry.pack(pady=10)
        self.entry.focus()

        ctk.CTkButton(self, text="OK", width=150, height=40, command=self._ok).pack(pady=10)
        self.bind("<Return>", lambda e: self._ok())

        self.result = None
        if parent:
            self.wait_window()
        else:
            self.mainloop()

    def _ok(self):
        self.result = self.password_var.get()
        self.destroy()

    @staticmethod
    def get_password(parent=None, title="Password", prompt="Enter password:"):
        try:
            return PasswordDialog(parent, title, prompt).result
        except Exception:
            log_error("Password dialog failed")
            return None

# ======================= PROGRESS DIALOG =========================
class ProgressDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Processing...", total=100):
        super().__init__(parent)
        self.title(title)
        self.geometry("500x150")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.attributes("-topmost", True)

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 250
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 75
        self.geometry(f"+{x}+{y}")

        self.label = ctk.CTkLabel(self, text="Starting...", font=("Segoe UI", 14))
        self.label.pack(pady=20)

        self.progress = ctk.CTkProgressBar(self, width=400)
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.cancelled = False
        ctk.CTkButton(self, text="Cancel", fg_color="darkred", command=self.cancel).pack(pady=10)

        self.total = total
        self.processed = 0

    def update(self, increment=1, text=None):
        self.processed += increment
        if text:
            self.label.configure(text=text)
        self.progress.set(self.processed / self.total)
        self.master.update()

    def cancel(self):
        self.cancelled = True

    def is_cancelled(self):
        return self.cancelled

# ======================= CRYPTO ENGINE =========================
class CryptoEngine:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> dict:
        iv = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return {
            "iv": base64.b64encode(iv).decode(),
            "ct": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(encryptor.tag).decode()
        }

    @staticmethod
    def decrypt(enc_data: dict, key: bytes) -> bytes:
        try:
            iv = base64.b64decode(enc_data["iv"])
            ct = base64.b64decode(enc_data["ct"])
            tag = base64.b64decode(enc_data["tag"])
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            return decryptor.update(ct) + decryptor.finalize()
        except InvalidTag:
            raise ValueError("Wrong password")

# ======================= STORAGE =========================
def load_master():
    if MASTER_FILE.exists():
        try:
            with open(MASTER_FILE, "r") as f:
                return json.load(f)
        except Exception:
            log_error("Failed to load master password file")
    return None

def save_master(salt_b64: str, check_b64: str):
    try:
        with open(MASTER_FILE, "w") as f:
            json.dump({"salt": salt_b64, "check": check_b64}, f)
    except Exception:
        log_error("Failed to save master password")

def load_items():
    if ITEMS_FILE.exists():
        try:
            with open(ITEMS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            log_error("Failed to load items list")
    return []

def save_items(items):
    try:
        with open(ITEMS_FILE, "w") as f:
            json.dump(items, f, indent=2)
    except Exception:
        log_error("Failed to save items list")

# ======================= WINDOW MONITOR =========================
class WindowMonitor:
    def __init__(self, folder_path: str, on_close_callback):
        self.folder_path = os.path.normpath(folder_path).lower()
        self.basename = os.path.basename(folder_path).lower()
        self.on_close_callback = on_close_callback
        self.running = False

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._monitor, daemon=True).start()

    def stop(self):
        self.running = False

    def _monitor(self):
        was_open = False
        closed_count = 0
        while self.running:
            time.sleep(1.2)
            is_open = self._is_open()
            if is_open:
                was_open = True
                closed_count = 0
            elif was_open:
                closed_count += 1
                if closed_count >= 3:
                    self.on_close_callback()
                    break

    def _is_open(self) -> bool:
        if sys.platform != "win32":
            return False
        found = [False]
        def enum(hwnd, _):
            try:
                if win32gui.IsWindowVisible(hwnd):
                    cls = win32gui.GetClassName(hwnd)
                    if cls in ("CabinetWClass", "ExploreWClass"):
                        title = win32gui.GetWindowText(hwnd).lower()
                        if self.folder_path in title or self.basename in title:
                            found[0] = True
                            return False
            except:
                pass
            return True
        try:
            win32gui.EnumWindows(enum, None)
        except:
            pass
        return found[0]

# ========================= MAIN APPLICATION =========================
class FolderLockerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Locker X")
        self.geometry("1000x700")
        self.configure(fg_color="#2b2b2b")

        self.items = load_items()
        self.monitors = {}

        self.authenticate_master()
        self.build_ui()

    def authenticate_master(self):
        data = load_master()
        if not data:
            self.setup_master()
            return

        salt = base64.b64decode(data["salt"])
        check = base64.b64decode(data["check"])

        for _ in range(5):
            pw = PasswordDialog.get_password(self, title="Authentication", prompt="Enter master password:")
            if not pw:
                sys.exit()
            key = CryptoEngine.derive_key(pw, salt)
            if hashlib.sha256(key).digest() == check:
                return
            messagebox.showerror("Error", "Wrong password")
        sys.exit("Too many attempts")

    def setup_master(self):
        while True:
            p1 = PasswordDialog.get_password(self, title="Setup", prompt="Create master password (min 8 chars):")
            if not p1 or len(p1) < 8:
                messagebox.showerror("Error", "Password too short")
                continue
            p2 = PasswordDialog.get_password(self, title="Setup", prompt="Confirm master password:")
            if p1 != p2:
                messagebox.showerror("Error", "Passwords don't match")
                continue
            break

        salt = secrets.token_bytes(SALT_LENGTH)
        key = CryptoEngine.derive_key(p1, salt)
        save_master(base64.b64encode(salt).decode(), base64.b64encode(hashlib.sha256(key).digest()).decode())
        messagebox.showinfo("Success", "Master password created")

    def build_ui(self):
        # Toolbar
        toolbar = ctk.CTkFrame(self, fg_color="#333333", height=60)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        left = ctk.CTkFrame(toolbar, fg_color="transparent")
        left.pack(side="left", padx=30)

        ctk.CTkButton(left, text="📁 Add Folder", width=150, command=self.add_folder).pack(side="left", padx=10, pady=10)
        ctk.CTkButton(left, text="📄 Add File", width=150, command=self.add_file).pack(side="left", padx=10, pady=10)

        right = ctk.CTkFrame(toolbar, fg_color="transparent")
        right.pack(side="right", padx=30)

        ctk.CTkButton(right, text="⚙ Settings", width=140, command=self.open_settings).pack(pady=10)

        # Main list
        main = ctk.CTkFrame(self, fg_color="#2b2b2b")
        main.pack(fill="both", expand=True, padx=40, pady=20)

        ctk.CTkLabel(main, text="Protected Items", font=("Segoe UI", 24, "bold")).pack(pady=(0, 20))

        self.list_frame = ctk.CTkScrollableFrame(main, fg_color="#2b2b2b")
        self.list_frame.pack(fill="both", expand=True)

        self.refresh_list()

    def refresh_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

        if not self.items:
            ctk.CTkLabel(self.list_frame, text="No protected items yet", text_color="gray", font=("Segoe UI", 16)).pack(pady=100)
            return

        for item in self.items:
            row = ctk.CTkFrame(self.list_frame, fg_color="#333333", corner_radius=12)
            row.pack(fill="x", pady=8, padx=20)

            icon = "📁" if item["type"] == "folder" else "📄"
            ctk.CTkLabel(row, text=f"{icon} {item['name']}", font=("Segoe UI", 16), anchor="w").pack(side="left", padx=20, pady=15)
            ctk.CTkLabel(row, text=f"Protected: {item['date']}", text_color="gray").pack(side="right", padx=20, pady=15)

            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right", padx=20)

            ctk.CTkButton(btns, text="Unlock", width=100, command=lambda i=item: self.temp_unlock(i)).pack(pady=3)
            ctk.CTkButton(btns, text="Remove", fg_color="darkred", width=100, command=lambda i=item: self.remove(i)).pack(pady=3)
            ctk.CTkButton(btns, text="Force Remove", fg_color="purple", width=100, command=lambda i=item: self.force_remove(i)).pack(pady=3)

    def add_folder(self):
        path = filedialog.askdirectory(title="Select folder to protect")
        if path:
            self._protect_thread(path, "folder")

    def add_file(self):
        path = filedialog.askopenfilename(title="Select file to protect")
        if path:
            self._protect_thread(path, "file")

    def _protect_thread(self, original_path: str, item_type: str):
        def task():
            if any(i["original_path"] == original_path for i in self.items):
                self.after(0, lambda: messagebox.showwarning("Warning", f"{item_type.capitalize()} already protected"))
                return

            name = Path(original_path).name
            pw = PasswordDialog.get_password(self, title="Set Password", prompt=f"Password for '{name}':")
            if not pw:
                return

            salt = secrets.token_bytes(SALT_LENGTH)
            key = CryptoEngine.derive_key(pw, salt)

            # Count files
            total = 0
            if item_type == "folder":
                for _, _, files in os.walk(original_path):
                    total += len([f for f in files if not f.endswith(".locked")])
            else:
                total = 1

            progress = ProgressDialog(self, title="Encrypting...", total=total)

            processed = 0
            try:
                if item_type == "folder":
                    for root, _, files in os.walk(original_path):
                        for file in files:
                            if progress.is_cancelled():
                                progress.destroy()
                                return
                            if not file.endswith(".locked"):
                                fp = os.path.join(root, file)
                                with open(fp, "rb") as f:
                                    data = f.read()
                                enc = CryptoEngine.encrypt(data, key)
                                with open(fp + ".locked", "w") as f:
                                    json.dump(enc, f)
                                os.remove(fp)
                                processed += 1
                                progress.update(1, f"Encrypting: {file}")
                else:
                    fp = original_path
                    with open(fp, "rb") as f:
                        data = f.read()
                    enc = CryptoEngine.encrypt(data, key)
                    with open(fp + ".locked", "w") as f:
                        json.dump(enc, f)
                    os.remove(fp)
                    processed = 1
                    progress.update(1, "Encrypting file...")
            except Exception as e:
                log_error(f"Encryption failed: {traceback.format_exc()}")
                self.after(0, lambda: messagebox.showerror("Error", "Encryption failed"))
                progress.destroy()
                return

            vault_name = f"{name}_{secrets.token_hex(8)}"
            vault_path = VAULT_DIR / vault_name

            try:
                if item_type == "folder":
                    os.rename(original_path, vault_path)
                else:
                    os.makedirs(vault_path, exist_ok=True)
                    os.rename(original_path + ".locked", vault_path / (Path(original_path).name + ".locked"))
            except Exception as e:
                log_error(f"Vault move failed: {traceback.format_exc()}")
                self.after(0, lambda: messagebox.showerror("Error", "Failed to hide item"))
                progress.destroy()
                return

            new_item = {
                "original_path": original_path,
                "vault_path": str(vault_path),
                "name": name,
                "type": item_type,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "salt": base64.b64encode(salt).decode()
            }
            self.items.append(new_item)
            save_items(self.items)
            self.after(0, self.refresh_list)
            progress.destroy()
            self.after(0, lambda: messagebox.showinfo("Success", f"'{name}' is now protected and hidden."))

        threading.Thread(target=task, daemon=True).start()

    def temp_unlock(self, item: dict):
        def task():
            pw = PasswordDialog.get_password(self, title="Unlock", prompt=f"Password for '{item['name']}':")
            if not pw:
                return

            salt = base64.b64decode(item["salt"])
            key = CryptoEngine.derive_key(pw, salt)

            total = 0
            if item["type"] == "folder":
                for _, _, files in os.walk(item["vault_path"]):
                    total += len([f for f in files if f.endswith(".locked")])
            else:
                total = 1

            progress = ProgressDialog(self, title="Decrypting...", total=total)
            processed = 0

            try:
                if item["type"] == "folder":
                    for root, _, files in os.walk(item["vault_path"]):
                        for file in files:
                            if progress.is_cancelled():
                                progress.destroy()
                                return
                            if file.endswith(".locked"):
                                fp = os.path.join(root, file)
                                with open(fp, "r") as f:
                                    enc = json.load(f)
                                data = CryptoEngine.decrypt(enc, key)
                                orig = fp[:-7]
                                with open(orig, "wb") as f:
                                    f.write(data)
                                os.remove(fp)
                                processed += 1
                                progress.update(1, f"Decrypting: {file}")
                else:
                    locked_file = list(Path(item["vault_path"]).glob("*.locked"))[0]
                    with open(locked_file, "r") as f:
                        enc = json.load(f)
                    data = CryptoEngine.decrypt(enc, key)
                    with open(item["original_path"], "wb") as f:
                        f.write(data)
                    os.remove(locked_file)
                    processed = 1
                    progress.update(1, "Decrypting file...")
            except ValueError:
                self.after(0, lambda: messagebox.showerror("Error", "Wrong password"))
                progress.destroy()
                return
            except Exception as e:
                log_error(f"Unlock failed: {traceback.format_exc()}")
                self.after(0, lambda: messagebox.showerror("Error", "Unlock failed"))
                progress.destroy()
                return

            try:
                if item["type"] == "folder":
                    os.rename(item["vault_path"], item["original_path"])
                    if sys.platform == "win32":
                        os.startfile(item["original_path"])
                    else:
                        subprocess.Popen(["xdg-open", item["original_path"]])
                else:
                    if sys.platform == "win32":
                        os.startfile(item["original_path"])
                    else:
                        subprocess.Popen(["xdg-open", item["original_path"]])
            except Exception as e:
                log_error(f"Open failed: {traceback.format_exc()}")

            if item["type"] == "folder":
                monitor = WindowMonitor(item["original_path"], lambda: self._relock(item, key))
                monitor.start()
                self.monitors[item["original_path"]] = monitor

            progress.destroy()
            self.after(0, lambda: messagebox.showinfo("Unlocked", f"'{item['name']}' is now accessible."))

        threading.Thread(target=task, daemon=True).start()

    def _relock(self, item: dict, key: bytes):
        def task():
            total = 0
            if item["type"] == "folder":
                for _, _, files in os.walk(item["original_path"]):
                    total += len([f for f in files if not f.endswith(".locked")])
            else:
                total = 1

            progress = ProgressDialog(self, title="Relocking...", total=total)
            processed = 0

            try:
                if item["type"] == "folder":
                    for root, _, files in os.walk(item["original_path"]):
                        for file in files:
                            if progress.is_cancelled():
                                progress.destroy()
                                return
                            if not file.endswith(".locked"):
                                fp = os.path.join(root, file)
                                with open(fp, "rb") as f:
                                    data = f.read()
                                enc = CryptoEngine.encrypt(data, key)
                                with open(fp + ".locked", "w") as f:
                                    json.dump(enc, f)
                                os.remove(fp)
                                processed += 1
                                progress.update(1, f"Encrypting: {file}")
                else:
                    with open(item["original_path"], "rb") as f:
                        data = f.read()
                    enc = CryptoEngine.encrypt(data, key)
                    locked_path = item["original_path"] + ".locked"
                    with open(locked_path, "w") as f:
                        json.dump(enc, f)
                    os.remove(item["original_path"])
                    processed = 1
                    progress.update(1, "Encrypting file...")
            except Exception as e:
                log_error(f"Relock failed: {traceback.format_exc()}")
                self.after(0, lambda: messagebox.showerror("Error", "Relock failed"))
                progress.destroy()
                return

            try:
                if item["type"] == "folder":
                    os.rename(item["original_path"], item["vault_path"])
                else:
                    os.makedirs(Path(item["vault_path"]), exist_ok=True)
                    os.rename(item["original_path"] + ".locked", Path(item["vault_path"]) / (Path(item["original_path"]).name + ".locked"))
            except Exception as e:
                log_error(f"Vault move on relock failed: {traceback.format_exc()}")

            if item["original_path"] in self.monitors:
                self.monitors[item["original_path"]].stop()
                del self.monitors[item["original_path"]]

            progress.destroy()
            self.after(0, lambda: messagebox.showinfo("Relocked", "Item secured again"))

        threading.Thread(target=task, daemon=True).start()

    def remove(self, item: dict):
        if not messagebox.askyesno("Confirm", f"Permanently remove protection from '{item['name']}'?"):
            return

        pw = PasswordDialog.get_password(self, title="Remove", prompt=f"Password for '{item['name']}':")
        if not pw:
            return

        salt = base64.b64decode(item["salt"])
        key = CryptoEngine.derive_key(pw, salt)

        total = 0
        if item["type"] == "folder":
            for _, _, files in os.walk(item["vault_path"]):
                total += len([f for f in files if f.endswith(".locked")])
        else:
            total = 1

        progress = ProgressDialog(self, title="Removing Protection...", total=total)
        processed = 0

        try:
            if item["type"] == "folder":
                for root, _, files in os.walk(item["vault_path"]):
                    for file in files:
                        if progress.is_cancelled():
                            progress.destroy()
                            return
                        if file.endswith(".locked"):
                            fp = os.path.join(root, file)
                            with open(fp, "r") as f:
                                enc = json.load(f)
                            data = CryptoEngine.decrypt(enc, key)
                            orig = fp[:-7]
                            with open(orig, "wb") as f:
                                f.write(data)
                            os.remove(fp)
                            processed += 1
                            progress.update(1, f"Decrypting: {file}")
            else:
                locked_file = list(Path(item["vault_path"]).glob("*.locked"))[0]
                with open(locked_file, "r") as f:
                    enc = json.load(f)
                data = CryptoEngine.decrypt(enc, key)
                with open(item["original_path"], "wb") as f:
                    f.write(data)
                os.remove(locked_file)
                processed = 1
                progress.update(1, "Decrypting file...")
        except ValueError:
            self.after(0, lambda: messagebox.showerror("Error", "Wrong password"))
            progress.destroy()
            return
        except Exception as e:
            log_error(f"Remove failed: {traceback.format_exc()}")
            self.after(0, lambda: messagebox.showerror("Error", "Remove failed"))
            progress.destroy()
            return

        try:
            if item["type"] == "folder":
                os.rename(item["vault_path"], item["original_path"])
        except Exception as e:
            log_error(f"Restore failed on remove: {traceback.format_exc()}")

        self.items = [i for i in self.items if i["original_path"] != item["original_path"]]
        save_items(self.items)
        self.after(0, self.refresh_list)
        progress.destroy()
        self.after(0, lambda: messagebox.showinfo("Success", "Protection removed"))

    def force_remove(self, item: dict):
        if not messagebox.askyesno("FORCE REMOVE", 
            f"WARNING: Permanently remove protection from '{item['name']}' WITHOUT password?\n"
            "All encrypted data will be LOST forever.\n"
            "Item will be restored if possible."):
            return

        try:
            if item["type"] == "folder":
                if Path(item["vault_path"]).exists():
                    os.rename(item["vault_path"], item["original_path"])
            else:
                Path(item["original_path"]).touch()
            messagebox.showinfo("Restored", "Item restored (encrypted content lost)")
        except Exception as e:
            log_error(f"Force remove failed: {traceback.format_exc()}")
            messagebox.showerror("Error", "Restore failed")

        self.items = [i for i in self.items if i["original_path"] != item["original_path"]]
        save_items(self.items)
        self.refresh_list()

    def open_settings(self):
        if hasattr(self, "settings_win") and self.settings_win.winfo_exists():
            self.settings_win.lift()
            return

        self.settings_win = ctk.CTkToplevel(self)
        self.settings_win.title("Settings")
        self.settings_win.geometry("450x450")
        self.settings_win.transient(self)
        self.settings_win.grab_set()
        self.settings_win.attributes("-topmost", True)

        self.settings_win.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - 225
        y = self.winfo_y() + (self.winfo_height() // 2) - 225
        self.settings_win.geometry(f"+{x}+{y}")

        ctk.CTkLabel(self.settings_win, text="Password Management", font=("Segoe UI", 20, "bold")).pack(pady=30)

        ctk.CTkButton(self.settings_win, text="Change Master Password", width=300, height=50,
                      fg_color="orange", command=self.change_master_password).pack(pady=15)

        ctk.CTkLabel(self.settings_win, text="Change Individual Item Password", font=("Segoe UI", 14)).pack(pady=(20, 10))

        item_frame = ctk.CTkScrollableFrame(self.settings_win, width=380, height=180)
        item_frame.pack(pady=10)

        for item in self.items:
            ctk.CTkButton(item_frame, text=f"{item['name']} ({item['type']})",
                          width=350, anchor="w", command=lambda i=item: self.change_item_password(i)).pack(pady=5, padx=10)

        self.settings_win.protocol("WM_DELETE_WINDOW", self._close_settings)

    def _close_settings(self):
        if hasattr(self, "settings_win"):
            self.settings_win.destroy()
            del self.settings_win

    def change_master_password(self):
        old_pw = PasswordDialog.get_password(self, title="Current Password", prompt="Enter current master password:")
        if not old_pw:
            return

        data = load_master()
        salt = base64.b64decode(data["salt"])
        check = base64.b64decode(data["check"])

        key = CryptoEngine.derive_key(old_pw, salt)
        if hashlib.sha256(key).digest() != check:
            messagebox.showerror("Error", "Wrong current password")
            return

        while True:
            p1 = PasswordDialog.get_password(self, title="New Password", prompt="New master password (min 8 chars):")
            if not p1 or len(p1) < 8:
                messagebox.showerror("Error", "Too short")
                continue
            p2 = PasswordDialog.get_password(self, title="Confirm", prompt="Confirm new password:")
            if p1 != p2:
                messagebox.showerror("Error", "No match")
                continue
            break

        new_salt = secrets.token_bytes(SALT_LENGTH)
        new_key = CryptoEngine.derive_key(p1, new_salt)
        save_master(base64.b64encode(new_salt).decode(), base64.b64encode(hashlib.sha256(new_key).digest()).decode())
        messagebox.showinfo("Success", "Master password changed")

    def change_item_password(self, item: dict):
        old_pw = PasswordDialog.get_password(self, title="Current Password", prompt=f"Current password for '{item['name']}':")
        if not old_pw:
            return

        salt = base64.b64decode(item["salt"])
        key = CryptoEngine.derive_key(old_pw, salt)

        # Test decryption
        try:
            test_file = next(Path(item["vault_path"]).rglob("*.locked")) if item["type"] == "folder" else list(Path(item["vault_path"]).glob("*.locked"))[0]
            with open(test_file, "r") as f:
                enc = json.load(f)
            CryptoEngine.decrypt(enc, key)
        except:
            messagebox.showerror("Error", "Wrong current password")
            return

        new_pw = PasswordDialog.get_password(self, title="New Password", prompt=f"New password for '{item['name']}':")
        if not new_pw:
            return

        new_salt = secrets.token_bytes(SALT_LENGTH)
        new_key = CryptoEngine.derive_key(new_pw, new_salt)

        total = 0
        if item["type"] == "folder":
            for _, _, files in os.walk(item["vault_path"]):
                total += len([f for f in files if f.endswith(".locked")])
        else:
            total = 1

        progress = ProgressDialog(self, title="Changing Password...", total=total)
        processed = 0

        try:
            if item["type"] == "folder":
                for root, _, files in os.walk(item["vault_path"]):
                    for file in files:
                        if progress.is_cancelled():
                            progress.destroy()
                            return
                        if file.endswith(".locked"):
                            fp = os.path.join(root, file)
                            with open(fp, "r") as f:
                                enc = json.load(f)
                            data = CryptoEngine.decrypt(enc, key)
                            new_enc = CryptoEngine.encrypt(data, new_key)
                            with open(fp, "w") as f:
                                json.dump(new_enc, f)
                            processed += 1
                            progress.update(1, f"Updating: {file}")
            else:
                locked_file = list(Path(item["vault_path"]).glob("*.locked"))[0]
                with open(locked_file, "r") as f:
                    enc = json.load(f)
                data = CryptoEngine.decrypt(enc, key)
                new_enc = CryptoEngine.encrypt(data, new_key)
                with open(locked_file, "w") as f:
                    json.dump(new_enc, f)
                processed = 1
                progress.update(1, "Updating file...")
        except Exception as e:
            log_error(f"Password change failed: {traceback.format_exc()}")
            self.after(0, lambda: messagebox.showerror("Error", "Password change failed"))
            progress.destroy()
            return

        item["salt"] = base64.b64encode(new_salt).decode()
        save_items(self.items)
        progress.destroy()
        messagebox.showinfo("Success", f"Password changed for '{item['name']}'")

if __name__ == "__main__":
    try:
        FolderLockerApp().mainloop()
    except Exception:
        log_error("Application crashed")
        messagebox.showerror("Fatal Error", "Application crashed. Check locker_errors.log")