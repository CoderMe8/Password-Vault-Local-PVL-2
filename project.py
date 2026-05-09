import os
import json
import hashlib
import base64
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
VAULT_DIR = "./vault_data"
CONFIG_FILE = os.path.join(VAULT_DIR, "config.json")
DATA_FILE = os.path.join(VAULT_DIR, "vault.enc")
CATEGORIES = ["Game", "Website", "E-mail", "Accounts"]

# Set Appearance
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

class SecurityManager:
    @staticmethod
    def hash_pin(pin):
        return hashlib.sha256(pin.encode()).hexdigest()

    @staticmethod
    def derive_key(pin, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

    @staticmethod
    def encrypt_data(data, key):
        f = Fernet(key)
        json_data = json.dumps(data).encode()
        return f.encrypt(json_data)

    @staticmethod
    def decrypt_data(encrypted_data, key):
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

class PasswordVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Secure Password Vault")
        self.geometry("1000x700")
        self.configure(fg_color="#F8FAFC") # Light professional background

        if not os.path.exists(VAULT_DIR):
            os.makedirs(VAULT_DIR)

        self.current_key = None
        self.vault_data = []
        self.edit_index = None
        self.in_update_mode = False

        self.show_auth_screen()

    def show_auth_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.auth_frame = ctk.CTkFrame(self, fg_color="white", corner_radius=15, border_width=1, border_color="#E2E8F0", width=400, height=350)
        self.auth_frame.place(relx=0.5, rely=0.5, anchor="center")

        title_label = ctk.CTkLabel(self.auth_frame, text="🔒 Password Vault", font=ctk.CTkFont(size=24, weight="bold"), text_color="#1E293B")
        title_label.pack(pady=(40, 20))

        is_setup = not os.path.exists(CONFIG_FILE)
        msg = "Set your Master PIN" if is_setup else "Enter your Master PIN"
        
        ctk.CTkLabel(self.auth_frame, text=msg, font=ctk.CTkFont(size=14), text_color="#64748B").pack(pady=5)

        self.pin_entry = ctk.CTkEntry(self.auth_frame, show="*", width=250, height=45, justify="center", font=ctk.CTkFont(size=18))
        self.pin_entry.pack(pady=20)
        self.pin_entry.focus()

        btn_text = "Create Vault" if is_setup else "Unlock"
        action_btn = ctk.CTkButton(self.auth_frame, text=btn_text, command=self.handle_auth, width=250, height=45, corner_radius=8, font=ctk.CTkFont(weight="bold"))
        action_btn.pack(pady=10)

        self.bind('<Return>', lambda e: self.handle_auth())

    def handle_auth(self):
        pin = self.pin_entry.get()
        if not pin or not pin.isdigit():
            messagebox.showerror("Error", "Please enter a valid numeric PIN")
            return

        if not os.path.exists(CONFIG_FILE):
            # First launch - Setup
            salt = os.urandom(16)
            config = {
                "pin_hash": SecurityManager.hash_pin(pin),
                "salt": base64.b64encode(salt).decode()
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f)
            
            self.current_key = SecurityManager.derive_key(pin, salt)
            self.save_vault([]) # Create empty encrypted file
            self.show_main_dashboard()
        else:
            # Login
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            
            if config["pin_hash"] == SecurityManager.hash_pin(pin):
                salt = base64.b64decode(config["salt"])
                self.current_key = SecurityManager.derive_key(pin, salt)
                try:
                    self.load_vault()
                    self.show_main_dashboard()
                except Exception as e:
                    messagebox.showerror("Error", "Failed to decrypt data. PIN might be correct but data is corrupted.")
            else:
                messagebox.showerror("Error", "Incorrect PIN")

    def load_vault(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "rb") as f:
                encrypted_content = f.read()
                if encrypted_content:
                    self.vault_data = SecurityManager.decrypt_data(encrypted_content, self.current_key)
                else:
                    self.vault_data = []
        else:
            self.vault_data = []

    def save_vault(self, data):
        encrypted = SecurityManager.encrypt_data(data, self.current_key)
        with open(DATA_FILE, "wb") as f:
            f.write(encrypted)

    def show_main_dashboard(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        self.unbind('<Return>')

        # Main Layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Top Search Bar ---
        search_frame = ctk.CTkFrame(self, fg_color="white", height=80, corner_radius=0, border_width=1, border_color="#E2E8F0")
        search_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(search_frame, text="🔍", font=ctk.CTkFont(size=20)).pack(side="left", padx=(20, 10))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.refresh_table())
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search by Source or Category...", 
                                         textvariable=self.search_var, width=600, height=40, border_width=1)
        self.search_entry.pack(side="left", pady=20)

        # --- Middle Table ---
        table_frame = ctk.CTkFrame(self, fg_color="white", corner_radius=10, border_width=1, border_color="#E2E8F0")
        table_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        
        # Styling Treeview to look like Excel
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background="white", 
                        foreground="#334155", 
                        rowheight=35, 
                        fieldbackground="white",
                        font=("Segoe UI", 10),
                        bordercolor="#E2E8F0",
                        borderwidth=1)
        style.map("Treeview", background=[('selected', '#3B82F6')], foreground=[('selected', 'white')])
        style.configure("Treeview.Heading", 
                        background="#F1F5F9", 
                        foreground="#475569", 
                        font=("Segoe UI", 10, "bold"), 
                        relief="flat")
        
        columns = ("#", "Source", "Category", "Username", "Password")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        
        # Column Headings
        self.tree.heading("#", text="#")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Username", text="Username / Email")
        self.tree.heading("Password", text="Password")

        # Column widths & alignment
        self.tree.column("#", width=50, anchor="center")
        self.tree.column("Source", width=200, anchor="w")
        self.tree.column("Category", width=150, anchor="center")
        self.tree.column("Username", width=250, anchor="w")
        self.tree.column("Password", width=200, anchor="w")

        # Scrollbar
        scrollbar = ctk.CTkScrollbar(table_frame, orientation="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

        # --- Bottom Input Panel ---
        self.input_frame = ctk.CTkFrame(self, fg_color="white", height=200, corner_radius=10, border_width=1, border_color="#E2E8F0")
        self.input_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(10, 20))

        # Input fields
        field_font = ctk.CTkFont(size=12)
        
        # Row 1 Labels
        ctk.CTkLabel(self.input_frame, text="Source", font=field_font).grid(row=0, column=0, padx=20, pady=(15, 0), sticky="w")
        ctk.CTkLabel(self.input_frame, text="Category", font=field_font).grid(row=0, column=1, padx=20, pady=(15, 0), sticky="w")
        ctk.CTkLabel(self.input_frame, text="Username", font=field_font).grid(row=0, column=2, padx=20, pady=(15, 0), sticky="w")
        ctk.CTkLabel(self.input_frame, text="Password", font=field_font).grid(row=0, column=3, padx=20, pady=(15, 0), sticky="w")

        # Row 2 Entries
        self.source_entry = ctk.CTkEntry(self.input_frame, width=200, height=35)
        self.source_entry.grid(row=1, column=0, padx=20, pady=(5, 15))

        self.category_dropdown = ctk.CTkComboBox(self.input_frame, values=CATEGORIES, width=150, height=35, state="readonly")
        self.category_dropdown.grid(row=1, column=1, padx=20, pady=(5, 15))
        self.category_dropdown.set(CATEGORIES[0])

        self.user_entry = ctk.CTkEntry(self.input_frame, width=200, height=35)
        self.user_entry.grid(row=1, column=2, padx=20, pady=(5, 15))

        self.pass_entry = ctk.CTkEntry(self.input_frame, width=200, height=35, show="*")
        self.pass_entry.grid(row=1, column=3, padx=20, pady=(5, 15))

        # Show/Hide Toggle
        self.show_pass = False
        self.toggle_btn = ctk.CTkButton(self.input_frame, text="👁️", width=40, height=35, fg_color="transparent", text_color="gray", command=self.toggle_pass)
        self.toggle_btn.grid(row=1, column=4, padx=(0, 20), pady=(5, 15))

        # Action Buttons
        btn_frame = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=5, pady=(0, 15))

        self.add_btn = ctk.CTkButton(btn_frame, text="Add Entry (+)", command=self.add_entry, width=120, height=40, font=ctk.CTkFont(weight="bold"))
        self.add_btn.pack(side="left", padx=10)

        self.clear_btn = ctk.CTkButton(btn_frame, text="Clear / New", command=self.clear_fields, width=120, height=40, fg_color="#64748B", hover_color="#475569", font=ctk.CTkFont(weight="bold"))
        self.clear_btn.pack(side="left", padx=10)

        self.delete_btn = ctk.CTkButton(btn_frame, text="Delete (-)", command=self.delete_entry, width=120, height=40, fg_color="#EF4444", hover_color="#DC2626", font=ctk.CTkFont(weight="bold"))
        self.delete_btn.pack(side="left", padx=10)

        ctk.CTkButton(btn_frame, text="Copy Username", command=lambda: self.copy_to_clipboard("user"), width=140, height=40, fg_color="#334155").pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Copy Password", command=lambda: self.copy_to_clipboard("pass"), width=140, height=40, fg_color="#334155").pack(side="left", padx=10)

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.bind('<Return>', lambda e: self.add_entry())
        self.refresh_table()

    def toggle_pass(self):
        self.show_pass = not self.show_pass
        self.pass_entry.configure(show="" if self.show_pass else "*")
        self.toggle_btn.configure(text="🔒" if self.show_pass else "👁️")

    def refresh_table(self):
        # Clear table
        for i in self.tree.get_children():
            self.tree.delete(i)

        query = self.search_var.get().strip().lower()
        
        count = 1
        for idx, item in enumerate(self.vault_data):
            # Dynamic filtering
            if query in item["source"].lower() or query in item["category"].lower():
                display_pass = "*" * len(item["password"])
                # Use iid=str(idx) for reliable index mapping
                self.tree.insert("", "end", iid=str(idx), values=(count, item["source"], item["category"], item["username"], display_pass))
                count += 1

    def on_tree_select(self, event):
        selection = self.tree.selection()
        if selection:
            # Get the original index directly from iid
            self.edit_index = int(selection[0])
            
            # Auto-fill fields immediately for better UX
            data = self.vault_data[self.edit_index]
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, data["source"])
            self.category_dropdown.set(data["category"])
            self.user_entry.delete(0, tk.END)
            self.user_entry.insert(0, data["username"])
            self.pass_entry.delete(0, tk.END)
            self.pass_entry.insert(0, data["password"])
            
            # Switch to update mode
            self.in_update_mode = True
            self.add_btn.configure(text="Save Changes ✔️", fg_color="#10B981", hover_color="#059669")

    def add_entry(self):
        source = self.source_entry.get().strip()
        category = self.category_dropdown.get()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not source or not user or not password:
            messagebox.showwarning("Warning", "All fields except Category are required!")
            return

        if self.in_update_mode:
            if messagebox.askyesno("Confirm Update", "Are you sure you want to save these changes?"):
                self.vault_data[self.edit_index] = {
                    "source": source,
                    "category": category,
                    "username": user,
                    "password": password
                }
                self.save_vault(self.vault_data)
                self.clear_fields()
                self.refresh_table()
                messagebox.showinfo("Success", "Entry updated successfully!")
            return

        new_entry = {
            "source": source,
            "category": category,
            "username": user,
            "password": password
        }

        self.vault_data.append(new_entry)
        self.save_vault(self.vault_data)
        self.clear_fields()
        self.refresh_table()
        messagebox.showinfo("Success", "Entry added successfully!")

    def update_entry(self):
        # This method is now effectively handled by on_tree_select
        # but kept as a helper for focus or manual trigger
        if self.edit_index is None:
            messagebox.showwarning("Warning", "Please click on an entry in the table first!")
            return
        self.source_entry.focus()

    def delete_entry(self):
        # Fallback: if edit_index is None, try to get it from current selection
        if self.edit_index is None:
            selection = self.tree.selection()
            if selection:
                self.edit_index = int(selection[0])
        
        if self.edit_index is None:
            messagebox.showwarning("Warning", "Select an entry to delete first!")
            return

        if messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?"):
            del self.vault_data[self.edit_index]
            self.save_vault(self.vault_data)
            self.clear_fields()
            self.refresh_table()

    def copy_to_clipboard(self, mode):
        # Use edit_index if set (most reliable), otherwise fallback to selection
        target_idx = self.edit_index
        
        if target_idx is None:
            selection = self.tree.selection()
            if selection:
                target_idx = int(selection[0])
        
        if target_idx is None:
            messagebox.showwarning("Warning", "Please click on an entry to select it first!")
            return
        
        try:
            data = self.vault_data[target_idx]
            text_to_copy = str(data["username"]) if mode == "user" else str(data["password"])
            
            # Robust clipboard update
            self.clipboard_clear()
            self.clipboard_append(text_to_copy)
            self.update() # Required for Windows to process the clipboard event
            
            messagebox.showinfo("Success", f"{'Username' if mode == 'user' else 'Password'} copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")

    def clear_fields(self):
        self.source_entry.delete(0, tk.END)
        self.category_dropdown.set(CATEGORIES[0])
        self.user_entry.delete(0, tk.END)
        self.pass_entry.delete(0, tk.END)
        self.edit_index = None
        self.in_update_mode = False
        self.add_btn.configure(text="Add Entry (+)", fg_color=["#3B82F6", "#1F6AA5"], hover_color=["#2563EB", "#144870"])

if __name__ == "__main__":
    app = PasswordVaultApp()
    app.mainloop()
