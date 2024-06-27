import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter import ttk
from ttkbootstrap import Style
import pyotp
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import time
import atexit


def read_config():
    with open("config.json", 'r') as config_file:
        config = json.load(config_file)
        return config['password'], config['salt'], config['totp_file']


PASS, SALT, totp_file = read_config()


def generate_fernet_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return key, encrypted_password


key, encrypted_password = generate_fernet_key(PASS, SALT)


def load_totps():
    try:
        with open(totp_file, 'rb') as file:
            encrypted_data = file.read()
            if not encrypted_data:
                return {}
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data)
    except FileNotFoundError:
        return {}
    except InvalidToken as e:
        return {}
    except Exception as e:
        return {}


def save_totps(totps):
    try:
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(json.dumps(totps).encode())
        with open(totp_file, 'wb') as file:
            file.write(encrypted_data)
    except Exception as e:
        return


class TOTPManager:
    def __init__(self, master):
        self.master = master
        self.style = Style(theme='cosmo')
        self.master.title("TOTP Manager")
        self.master.geometry('400x300')
        self.listbox = None
        self.authenticate()
        atexit.register(self.save_totps_on_exit)

    def authenticate(self):
        password = simpledialog.askstring("Authentication", "Enter password:", show='*')
        if not password or not self.verify_password(password):
            messagebox.showerror("Error", "Authentication Failed")
            self.master.destroy()
        else:
            self.show_main_menu()

    def verify_password(self, password):
        try:
            cipher_suite = Fernet(key)
            decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
            return password == decrypted_password
        except Exception as e:
            print(f"Error verifying password: {e}")
            return False

    def show_main_menu(self):
        self.clear_widgets()
        frame = ttk.Frame(self.master, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="TOTP Manager", style='primary.TLabel', font=('Helvetica', 16)).pack(pady=10)
        ttk.Button(frame, text="Insert new TOTP", command=self.insert_totp, style='primary.TButton').pack(pady=10, fill=tk.X)
        ttk.Button(frame, text="Get TOTP code", command=self.get_totp_code, style='primary.TButton').pack(pady=10, fill=tk.X)
        ttk.Button(frame, text="Remove TOTP", command=self.prepare_remove_totp, style='danger.TButton').pack(pady=10, fill=tk.X)
        ttk.Button(frame, text="Close", command=self.close_application, style='danger.TButton').pack(pady=10, fill=tk.X)
        self.load_and_display_totps()

    def prepare_remove_totp(self):
        self.clear_widgets()
        frame = ttk.Frame(self.master, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Select TOTP to Remove", style='primary.TLabel', font=('Helvetica', 14)).pack(pady=10)
        totps = load_totps()
        if not totps:
            messagebox.showinfo("Info", "No TOTP available")
            self.show_main_menu()
            return
        self.listbox = tk.Listbox(frame, height=6, font=('Helvetica', 12))
        self.listbox.pack(pady=10, fill=tk.BOTH, expand=True)
        for name in totps.keys():
            self.listbox.insert(tk.END, name)
        ttk.Button(frame, text="Remove TOTP", command=self.remove_totp, style='danger.TButton').pack(pady=10, fill=tk.X)
        ttk.Button(frame, text="Back", command=self.show_main_menu, style='secondary.TButton').pack(fill=tk.X)

    def insert_totp(self):
        self.clear_widgets()
        frame = ttk.Frame(self.master, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Insert New TOTP", style='primary.TLabel', font=('Helvetica', 14)).pack(pady=10)
        ttk.Label(frame, text="Name:", style='TLabel').pack(anchor='w')
        self.name_entry = ttk.Entry(frame, width=30)
        self.name_entry.pack(pady=5)
        ttk.Label(frame, text="TOTP Secret:", style='TLabel').pack(anchor='w')
        self.secret_entry = ttk.Entry(frame, width=30)
        self.secret_entry.pack(pady=5)
        ttk.Button(frame, text="Save", command=self.save_totp, style='success.TButton').pack(pady=10, fill=tk.X)
        ttk.Button(frame, text="Back", command=self.show_main_menu, style='secondary.TButton').pack(fill=tk.X)

    def save_totp(self):
        name = self.name_entry.get()
        secret = self.secret_entry.get()
        if name and secret:
            try:
                pyotp.TOTP(secret).now()
                totps = load_totps()
                if name in totps:
                    messagebox.showerror("Error", "TOTP name already exists")
                else:
                    totps[name] = secret
                    save_totps(totps)
                    messagebox.showinfo("Success", "TOTP saved successfully")
                    self.show_main_menu()
            except:
                messagebox.showerror("Error", "Invalid TOTP code")
        else:
            messagebox.showerror("Error", "All fields are required")

    def get_totp_code(self):
        self.clear_widgets()
        frame = ttk.Frame(self.master, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Select TOTP", style='primary.TLabel', font=('Helvetica', 14)).pack(pady=10)
        totps = load_totps()
        if not totps:
            messagebox.showinfo("Info", "No TOTP available")
            self.show_main_menu()
            return
        self.listbox = tk.Listbox(frame, height=6, font=('Helvetica', 12))
        self.listbox.pack(pady=10, fill=tk.BOTH, expand=True)
        for name in totps.keys():
            self.listbox.insert(tk.END, name)
        ttk.Button(frame, text="Get Code", command=self.show_totp_code, style='success.TButton').pack(pady=10, fill=tk.X)
        ttk.Button(frame, text="Back", command=self.show_main_menu, style='secondary.TButton').pack(fill=tk.X)

    def show_totp_code(self):
        if not self.listbox:
            messagebox.showerror("Error", "No TOTP selected")
            return

        selected_name = self.listbox.get(tk.ACTIVE)
        if not selected_name:
            messagebox.showerror("Error", "No TOTP selected")
            return
        self.clear_widgets()
        frame = ttk.Frame(self.master, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="TOTP Code", style='primary.TLabel', font=('Helvetica', 14)).pack(pady=10)
        totps = load_totps()
        secret = totps[selected_name]
        self.totp = pyotp.TOTP(secret)
        self.code_label = ttk.Label(frame, text="", style='primary.TLabel', font=('Helvetica', 12))
        self.code_label.pack(pady=10)
        self.update_totp_code()
        ttk.Button(frame, text="Back", command=self.get_totp_code, style='secondary.TButton').pack(fill=tk.X)

    def update_totp_code(self):
        try:
            code = self.totp.now()
            remaining = 30 - int(time.time()) % 30
            self.code_label.config(text=f"Code: {code}\nValid for: {remaining} seconds")
            self.master.after(1000, self.update_totp_code)  # Update every second
        except Exception as e:
            print(f"Error updating TOTP code: {e}")

    def remove_totp(self):
        if not self.listbox:
            messagebox.showerror("Error", "No TOTP selected")
            return

        selected_name = self.listbox.get(tk.ACTIVE)
        if not selected_name:
            messagebox.showerror("Error", "No TOTP selected")
            return
        totps = load_totps()
        if selected_name in totps:
            del totps[selected_name]
            save_totps(totps)
            messagebox.showinfo("Success", f"TOTP '{selected_name}' removed successfully")
            self.show_main_menu()
        else:
            messagebox.showerror("Error", f"TOTP '{selected_name}' not found")

    def clear_widgets(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def save_totps_on_exit(self):
        totps = load_totps()
        save_totps(totps)

    def close_application(self):
        self.save_totps_on_exit()
        self.master.destroy()

    def load_and_display_totps(self):
        load_totps()


if __name__ == "__main__":
    root = tk.Tk()
    app = TOTPManager(root)
    root.mainloop()