import os
import time
import tkinter as tk
from tkinter import messagebox
import random
import string

from crypto_utils import encrypt_vault, decrypt_vault

VAULT_FILE = "vault.json.enc"
AUTO_LOCK_SECONDS = 180
CLIPBOARD_CLEAR_SECONDS = 15
PASSWORD_MAX_AGE_DAYS = 90

# ---------- UTILS ----------
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def password_strength_score(pwd):
    score = 0
    if len(pwd) >= 8: score += 1
    if any(c.isupper() for c in pwd): score += 1
    if any(c.islower() for c in pwd): score += 1
    if any(c.isdigit() for c in pwd): score += 1
    if any(not c.isalnum() for c in pwd): score += 1
    return score

def password_is_old(ts):
    return (time.time() - ts) / 86400 > PASSWORD_MAX_AGE_DAYS

# ---------- MAIN APP ----------
class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager (Raspberry Pi)")
        self.root.geometry("760x540")
        self.root.configure(bg="#eef2f6")

        self.master_password = None
        self.vault = {}
        self.last_activity = time.time()
        self.status = tk.StringVar(value="Ready")

        self.root.bind_all("<Any-KeyPress>", self._activity)
        self.root.bind_all("<Any-Button>", self._activity)

        self._auto_lock_loop()

        if os.path.exists(VAULT_FILE):
            self._login_screen()
        else:
            self._first_run_screen()

    # ---------- CORE ----------
    def _activity(self, event=None):
        self.last_activity = time.time()

    def _auto_lock_loop(self):
        if self.master_password and time.time() - self.last_activity > AUTO_LOCK_SECONDS:
            self._lock("Auto-locked due to inactivity")
        self.root.after(1000, self._auto_lock_loop)

    def _lock(self, msg=None):
        if msg:
            messagebox.showinfo("Vault Locked", msg)
        self.master_password = None
        self.vault = {}
        self._login_screen()

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _header(self, text):
        tk.Label(self.root, text=text, font=("Segoe UI", 18, "bold"),
                 bg="#eef2f6").pack(pady=10)
        tk.Label(self.root, text="Offline • Encrypted • Raspberry Pi",
                 fg="gray", bg="#eef2f6").pack()

    # ---------- FIRST RUN ----------
    def _first_run_screen(self):
        self._clear()
        self._header("Create Master Password")

        box = tk.Frame(self.root, bg="white", padx=25, pady=25)
        box.pack(pady=30)

        tk.Label(box, text="Master Password").pack(anchor="w")
        self.pwd1 = tk.Entry(box, show="*", width=35)
        self.pwd1.pack()

        self.strength_lbl = tk.Label(box, text="Strength: ", fg="gray")
        self.strength_lbl.pack(anchor="w")
        self.pwd1.bind("<KeyRelease>", lambda e:
            self.strength_lbl.config(
                text=f"Strength: {password_strength_score(self.pwd1.get())}/5"
            ))

        tk.Label(box, text="Confirm Password").pack(anchor="w")
        self.pwd2 = tk.Entry(box, show="*", width=35)
        self.pwd2.pack()

        tk.Button(box, text="Create Vault",
                  bg="#0078d7", fg="white",
                  command=self._create_vault).pack(pady=15)

    def _create_vault(self):
        if self.pwd1.get() != self.pwd2.get():
            messagebox.showerror("Error", "Passwords do not match")
            return
        if password_strength_score(self.pwd1.get()) < 3:
            messagebox.showerror("Weak Password", "Choose a stronger password")
            return
        self.master_password = self.pwd1.get()
        self.vault = {}
        self._save()
        self._dashboard()

    # ---------- LOGIN ----------
    def _login_screen(self):
        self._clear()
        self._header("Unlock Vault")

        box = tk.Frame(self.root, bg="white", padx=25, pady=25)
        box.pack(pady=30)

        tk.Label(box, text="Master Password").pack()
        self.login_pwd = tk.Entry(box, show="*", width=35)
        self.login_pwd.pack()

        tk.Button(box, text="Unlock",
                  bg="#0078d7", fg="white",
                  command=self._unlock).pack(pady=10)

    def _unlock(self):
        try:
            with open(VAULT_FILE, "rb") as f:
                self.vault = decrypt_vault(self.login_pwd.get(), f.read())
            self.master_password = self.login_pwd.get()
            self._dashboard()
        except:
            messagebox.showerror("Error", "Invalid master password")

    # ---------- DASHBOARD ----------
    def _dashboard(self):
        self._clear()
        self._header("Password Vault")

        self.search = tk.Entry(self.root, width=45)
        self.search.pack(pady=5)
        self.search.bind("<KeyRelease>", lambda e: self._refresh())

        self.listbox = tk.Listbox(self.root, width=65, height=14)
        self.listbox.pack(pady=10)
        self._refresh()

        btns = tk.Frame(self.root, bg="#eef2f6")
        btns.pack()

        tk.Button(btns, text="Add", width=12, command=self._add).grid(row=0, column=0, padx=5)
        tk.Button(btns, text="Edit", width=12, command=self._edit).grid(row=0, column=1, padx=5)
        tk.Button(btns, text="Copy", width=12, command=self._copy).grid(row=0, column=2, padx=5)
        tk.Button(btns, text="Delete", width=12, command=self._delete).grid(row=0, column=3, padx=5)
        tk.Button(btns, text="Audit", width=12, command=self._audit).grid(row=0, column=4, padx=5)
        tk.Button(btns, text="Lock", width=12, command=lambda: self._lock("Vault locked")).grid(row=0, column=5, padx=5)

        tk.Label(self.root, textvariable=self.status,
                 bg="#dde3ea", anchor="w").pack(fill="x", side="bottom")

    def _refresh(self):
        self.listbox.delete(0, tk.END)
        query = self.search.get().lower()
        for site, data in sorted(self.vault.items()):
            label = site
            if "created_at" in data and password_is_old(data["created_at"]):
                label += "  (OLD)"
            if query in site.lower():
                self.listbox.insert(tk.END, label)

    # ---------- VAULT OPS ----------
    def _get_selected_site(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showerror("Error", "Select an entry")
            return None
        return self.listbox.get(sel[0]).split("  ")[0]

    def _entry_popup(self, title, site=None):
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.geometry("350x330")
        popup.transient(self.root)
        popup.grab_set()
        popup.focus_force()

        tk.Label(popup, text="Site").pack()
        site_e = tk.Entry(popup, width=35)
        site_e.pack()

        tk.Label(popup, text="Username").pack()
        user_e = tk.Entry(popup, width=35)
        user_e.pack()

        tk.Label(popup, text="Password").pack()
        pwd_e = tk.Entry(popup, width=35, show="*")
        pwd_e.pack()

        tk.Checkbutton(
            popup, text="Show Password",
            command=lambda: pwd_e.config(show="" if pwd_e.cget("show") else "*")
        ).pack()

        tk.Button(
            popup, text="Generate Strong Password",
            command=lambda: pwd_e.delete(0, tk.END) or pwd_e.insert(0, generate_password())
        ).pack(pady=5)

        if site:
            site_e.insert(0, site)
            site_e.config(state="disabled")
            user_e.insert(0, self.vault[site]["username"])
            pwd_e.insert(0, self.vault[site]["password"])

        def save():
            key = site if site else site_e.get()
            if not key:
                messagebox.showerror("Error", "Site required")
                return
            self.vault[key] = {
                "username": user_e.get(),
                "password": pwd_e.get(),
                "created_at": self.vault.get(key, {}).get("created_at", time.time())
            }
            self._save()
            popup.destroy()
            self.status.set("Entry saved")

        tk.Button(popup, text="Save",
                  bg="#0078d7", fg="white",
                  command=save).pack(pady=10)

    def _add(self):
        self._entry_popup("Add Entry")

    def _edit(self):
        site = self._get_selected_site()
        if site:
            self._entry_popup("Edit Entry", site)

    def _copy(self):
        site = self._get_selected_site()
        if site:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.vault[site]["password"])
            self.status.set("Password copied (auto-clear in 15s)")
            self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000,
                            self.root.clipboard_clear)

    def _delete(self):
        site = self._get_selected_site()
        if site and messagebox.askyesno("Confirm", f"Delete {site}?"):
            del self.vault[site]
            self._save()
            self.status.set("Entry deleted")

    def _audit(self):
        weak, reused = [], set()
        seen = {}
        for site, data in self.vault.items():
            pwd = data["password"]
            if len(pwd) < 10:
                weak.append(site)
            if pwd in seen:
                reused.add(site)
                reused.add(seen[pwd])
            else:
                seen[pwd] = site
        report = ""
        if weak:
            report += "Weak passwords:\n" + "\n".join(weak) + "\n\n"
        if reused:
            report += "Reused passwords:\n" + "\n".join(reused)
        messagebox.showinfo("Security Audit", report or "No issues detected")

    def _save(self):
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_vault(self.master_password, self.vault))
        self._refresh()

# ---------- RUN ----------
if __name__ == "__main__":
    root = tk.Tk()
    PasswordManager(root)
    root.mainloop()
