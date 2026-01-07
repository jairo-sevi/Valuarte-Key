import os
import sys
import sqlite3
import bcrypt
import base64
import secrets
import string
import pyperclip
import customtkinter as ctk
from tkinter import messagebox

# Librerías de criptografía
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ==============================================================================
# --- BACKEND (Valuarte Core Engine) ---
# ==============================================================================

DB_NAME = "valuarte_key.db"

class SecurityBackend:
    def __init__(self):
        # --- FIX DE PERSISTENCIA PARA .EXE ---
        # Detectamos si estamos corriendo como ejecutable congelado (PyInstaller)
        if getattr(sys, 'frozen', False):
            # Si es un .exe, la ruta base es donde está el ejecutable
            base_path = os.path.dirname(sys.executable)
        else:
            # Si es un script .py, la ruta base es donde está el archivo
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        self.db_path = os.path.join(base_path, DB_NAME)
        # -------------------------------------
        
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.fernet = None
        self._init_db()

    def _init_db(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                master_hash BLOB NOT NULL,
                secret_answer_hash BLOB NOT NULL,
                salt BLOB NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def is_setup_complete(self):
        self.cursor.execute("SELECT id FROM config LIMIT 1")
        return self.cursor.fetchone() is not None

    def register_user(self, master_password, secret_answer):
        try:
            salt = os.urandom(16)
            mp_bytes = master_password.encode('utf-8')
            sa_bytes = secret_answer.lower().strip().encode('utf-8')
            
            master_hash = bcrypt.hashpw(mp_bytes, bcrypt.gensalt(rounds=12))
            answer_hash = bcrypt.hashpw(sa_bytes, bcrypt.gensalt(rounds=12))
            
            self.cursor.execute("DELETE FROM config") 
            self.cursor.execute('INSERT INTO config (master_hash, secret_answer_hash, salt) VALUES (?, ?, ?)', 
                                (master_hash, answer_hash, salt))
            self.conn.commit()
            self._derive_key(master_password, salt)
            return True
        except Exception as e:
            print(f"Error crítico DB: {e}")
            return False

    def login(self, master_password, secret_answer):
        self.cursor.execute("SELECT master_hash, secret_answer_hash, salt FROM config")
        data = self.cursor.fetchone()
        if not data: return False
        
        stored_mp_hash, stored_sa_hash, salt = data
        
        if not bcrypt.checkpw(master_password.encode('utf-8'), stored_mp_hash): return False
        if not bcrypt.checkpw(secret_answer.lower().strip().encode('utf-8'), stored_sa_hash): return False
        
        self._derive_key(master_password, salt)
        return True

    def verify_secret_for_reset(self, secret_answer):
        self.cursor.execute("SELECT secret_answer_hash FROM config")
        data = self.cursor.fetchone()
        if not data: return False
        stored_sa_hash = data[0]
        return bcrypt.checkpw(secret_answer.lower().strip().encode('utf-8'), stored_sa_hash)

    def factory_reset(self):
        try:
            self.cursor.execute("DROP TABLE IF EXISTS config")
            self.cursor.execute("DROP TABLE IF EXISTS vault")
            self.conn.commit()
            self._init_db()
            return True
        except Exception as e:
            print(f"Error reset: {e}")
            return False

    def _derive_key(self, master_password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet = Fernet(key)

    def save_password_to_vault(self, site, password_plain):
        if not self.fernet: return False
        try:
            enc_pass = self.fernet.encrypt(password_plain.encode())
            self.cursor.execute("INSERT INTO vault (site_name, encrypted_password) VALUES (?, ?)", (site, enc_pass))
            self.conn.commit()
            return True
        except Exception: return False

    def get_vault_items(self):
        if not self.fernet: return []
        self.cursor.execute("SELECT id, site_name, encrypted_password FROM vault ORDER BY site_name ASC")
        rows = self.cursor.fetchall()
        items = []
        for rid, site, enc_pass in rows:
            try:
                dec_pass = self.fernet.decrypt(enc_pass).decode()
                items.append((rid, site, dec_pass))
            except: items.append((rid, site, "Error: Data Corruption"))
        return items

    def delete_vault_item(self, item_id):
        self.cursor.execute("DELETE FROM vault WHERE id = ?", (item_id,))
        self.conn.commit()

backend = SecurityBackend()

# ==============================================================================
# --- LÓGICA DE FUERZA BRUTA Y GENERACIÓN ---
# ==============================================================================

def generar_contrasena(longitud, u_min, u_may, u_num, u_sym):
    tipos = []
    if u_min: tipos.append(string.ascii_lowercase)
    if u_may: tipos.append(string.ascii_uppercase)
    if u_num: tipos.append(string.digits)
    if u_sym: tipos.append("!@#$%^&*()_+-=")
    
    if not tipos: return "⚠️ Selecciona opciones"
    try:
        longitud = int(longitud)
    except:
        return "⚠️ Longitud inválida"

    if longitud < len(tipos): return "⚠️ Longitud insuficiente"
    
    pwd = [secrets.choice(t) for t in tipos]
    all_chars = "".join(tipos)
    for _ in range(longitud - len(tipos)): pwd.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(pwd)
    return ''.join(pwd)

def evaluar_fortaleza_logica(contrasena):
    if not contrasena: return 0, "Vacía", "gray"
    
    pts = len(contrasena) * 3 
    if any(c.islower() for c in contrasena): pts += 5
    if any(c.isupper() for c in contrasena): pts += 5
    if any(c.isdigit() for c in contrasena): pts += 5
    if any(c in "!@#$%^&*()_+-=" for c in contrasena): pts += 10
    
    if len(contrasena) > 20: pts += 20
    if len(contrasena) > 50: pts += 50

    if pts < 40: return pts, "Muy Vulnerable 🔴", "#ef5350"
    if pts < 80: return pts, "Débil 🟠", "#ffa726"
    if pts < 120: return pts, "Aceptable 🟡", "#ffee58"
    if pts < 160: return pts, "Robusta 🟢", "#66bb6a"
    return pts, "Blindada (Militar) 🛡️", "#2e7d32"

# ==============================================================================
# --- INTERFAZ GRÁFICA (Valuarte Key UI) ---
# ==============================================================================

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Valuarte Key | Security Suite")
        self.geometry("550x850")
        
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)

        if backend.is_setup_complete():
            self.show_login()
        else:
            self.show_setup()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    # --- FIRMA DEL PENTESTER ---
    def add_signature(self, parent_frame):
        sig_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        sig_frame.pack(side="bottom", pady=15)
        
        ctk.CTkFrame(sig_frame, height=1, width=200, fg_color="gray40").pack(pady=5)
        
        ctk.CTkLabel(sig_frame, text="Developed by Jairo Sevillano | eJPTv2 Certified", 
                     font=("Consolas", 10), text_color="gray60").pack()
        ctk.CTkLabel(sig_frame, text="valuarte.digital Security Labs", 
                     font=("Consolas", 10, "bold"), text_color="#3B8ED0").pack()
        ctk.CTkLabel(sig_frame, text="[System: AES-256 Encrypted]", 
                     font=("Consolas", 9), text_color="#66bb6a").pack(pady=(2,0))

    # --- PANTALLAS ---
    
    def show_login(self):
        self.clear_container()
        frame = ctk.CTkFrame(self.container, corner_radius=15)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="VALUARTE KEY", font=("Impact", 28), text_color=("#1f538d", "#4b91d6")).pack(pady=(30, 5), padx=50)
        ctk.CTkLabel(frame, text="Secure Access Point", font=("Arial", 11, "bold"), text_color="gray").pack(pady=(0, 20))
        
        self.entry_mp = ctk.CTkEntry(frame, placeholder_text="Contraseña Maestra", show="•", width=260, height=35)
        self.entry_mp.pack(pady=10)
        self.entry_mp.bind("<Return>", lambda event: self.attempt_login())
        
        ctk.CTkLabel(frame, text="Respuesta Secreta (2FA):", font=("Arial", 10)).pack(pady=(5,0))
        self.entry_sa = ctk.CTkEntry(frame, placeholder_text="", show="•", width=260, height=35)
        self.entry_sa.pack(pady=5)
        self.entry_sa.bind("<Return>", lambda event: self.attempt_login())
        
        ctk.CTkButton(frame, text="DESBLOQUEAR", command=self.attempt_login, width=260, height=45, 
                      font=("Arial", 13, "bold")).pack(pady=20)
        
        ctk.CTkButton(frame, text="¿Olvidaste tu contraseña?", command=self.show_reset_dialog, 
                      fg_color="transparent", text_color=("#1f538d", "#4b91d6"), 
                      font=("Arial", 11, "underline"), hover_color=("gray85", "gray25")).pack(pady=(0, 10))
        
        self.lbl_error = ctk.CTkLabel(frame, text="", text_color="#ef5350")
        self.lbl_error.pack(pady=(0, 10))
        
        self.add_signature(frame)

    def show_setup(self):
        self.clear_container()
        frame = ctk.CTkFrame(self.container, corner_radius=15)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="⚙️ SETUP VALUARTE", font=("Impact", 24)).pack(pady=(30, 20), padx=50)
        
        self.entry_mp = ctk.CTkEntry(frame, placeholder_text="Nueva Contraseña Maestra", show="•", width=260)
        self.entry_mp.pack(pady=5)
        self.entry_conf = ctk.CTkEntry(frame, placeholder_text="Confirmar Contraseña", show="•", width=260)
        self.entry_conf.pack(pady=5)
        
        ctk.CTkLabel(frame, text="Establece tu Respuesta Secreta:", text_color="gray").pack(pady=(15, 0))
        self.entry_sa = ctk.CTkEntry(frame, placeholder_text="", width=260)
        self.entry_sa.pack(pady=5)
        
        ctk.CTkButton(frame, text="GUARDAR Y EMPEZAR", command=self.attempt_setup, 
                      fg_color="#2e7d32", hover_color="#1b5e20", width=260, height=40).pack(pady=25)
        
        self.lbl_error = ctk.CTkLabel(frame, text="", text_color="#ef5350")
        self.lbl_error.pack(pady=(0, 10))
        
        self.add_signature(frame)

    # --- LÓGICA LOGIN / SETUP / RESET ---

    def attempt_login(self):
        if backend.login(self.entry_mp.get(), self.entry_sa.get()):
            self.show_main_app()
        else:
            self.lbl_error.configure(text="⛔ Acceso Denegado")
            self.entry_mp.delete(0, 'end')
            self.entry_sa.delete(0, 'end')

    def show_reset_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Recuperación de Cuenta")
        dialog.geometry("400x300")
        dialog.transient(self)
        
        ctk.CTkLabel(dialog, text="⚠️ RESET DE EMERGENCIA", font=("Arial", 16, "bold"), text_color="#c62828").pack(pady=20)
        ctk.CTkLabel(dialog, text="Si olvidaste la contraseña maestra,\nno podemos desencriptar tus datos antiguos.", font=("Arial", 12)).pack(pady=5)
        ctk.CTkLabel(dialog, text="Usa tu Respuesta Secreta para borrar\nla cuenta y crear una nueva:", font=("Arial", 12)).pack(pady=10)
        
        entry_secret = ctk.CTkEntry(dialog, placeholder_text="Respuesta Secreta", show="•", width=250)
        entry_secret.pack(pady=10)
        
        def confirm_reset():
            secret = entry_secret.get()
            if backend.verify_secret_for_reset(secret):
                confirm = messagebox.askyesno("Confirmar Borrado", 
                                              "¡ATENCIÓN!\n\nEsto borrará PERMANENTEMENTE todas las contraseñas guardadas para permitirte empezar de cero.\n\n¿Estás seguro?")
                if confirm:
                    if backend.factory_reset():
                        messagebox.showinfo("Reset Completo", "El sistema se ha reiniciado. Configura tu nueva contraseña.")
                        dialog.destroy()
                        self.show_setup()
                    else:
                        messagebox.showerror("Error", "No se pudo resetear la base de datos.")
            else:
                messagebox.showerror("Error", "La respuesta secreta es incorrecta.")

        ctk.CTkButton(dialog, text="VERIFICAR Y RESETEAR", fg_color="#c62828", hover_color="#b71c1c", command=confirm_reset).pack(pady=20)

    def attempt_setup(self):
        if self.entry_mp.get() != self.entry_conf.get():
            self.lbl_error.configure(text="Las contraseñas no coinciden")
            return
        if not self.entry_mp.get() or not self.entry_sa.get():
            self.lbl_error.configure(text="Todos los campos son obligatorios")
            return
            
        if backend.register_user(self.entry_mp.get(), self.entry_sa.get()):
            self.show_main_app()
        else:
            self.lbl_error.configure(text="Error de escritura en disco")

    # --- APLICACIÓN PRINCIPAL ---

    def show_main_app(self):
        self.clear_container()
        
        header = ctk.CTkFrame(self.container, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        ctk.CTkLabel(title_frame, text="VALUARTE KEY", font=("Impact", 20), text_color="#3B8ED0").pack(anchor="w")
        
        current_user = os.getlogin()
        ctk.CTkLabel(title_frame, text=f"System User: {current_user}", font=("Consolas", 10), text_color="gray").pack(anchor="w")

        ctk.CTkButton(header, text="Lock", width=60, fg_color="transparent", border_width=1, 
                      text_color=("gray10", "gray90"), command=self.quit).pack(side="right")

        self.tabs = ctk.CTkTabview(self.container)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.tab_gen = self.tabs.add("  Generador  ")
        self.tab_vault = self.tabs.add("  Mis Claves Guardadas  ")
        
        self.setup_generator_tab()
        self.setup_vault_tab()

    def setup_generator_tab(self):
        scroll_frame = ctk.CTkScrollableFrame(self.tab_gen, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True)

        ctk.CTkLabel(scroll_frame, text="GENERADOR DE CLAVES", font=("Arial", 12, "bold"), text_color="gray").pack(anchor="w", padx=10)
        
        opts_frame = ctk.CTkFrame(scroll_frame)
        opts_frame.pack(fill="x", pady=5, padx=10)
        
        self.chk_vars = [ctk.IntVar(value=1) for _ in range(4)]
        labels = ["a-z", "A-Z", "0-9", "#$%"]
        for i, txt in enumerate(labels):
            ctk.CTkCheckBox(opts_frame, text=txt, variable=self.chk_vars[i], width=60).pack(side="left", expand=True, pady=10)
            
        slider_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        slider_frame.pack(fill="x", padx=20, pady=5)
        
        ctk.CTkLabel(slider_frame, text="Longitud:", font=("Arial", 12)).pack(side="left")
        
        self.slider = ctk.CTkSlider(slider_frame, from_=4, to=100, number_of_steps=96, command=self.update_entry_from_slider)
        self.slider.set(16)
        self.slider.pack(side="left", fill="x", expand=True, padx=10)
        
        self.entry_len = ctk.CTkEntry(slider_frame, width=50, justify="center")
        self.entry_len.insert(0, "16")
        self.entry_len.pack(side="right")
        self.entry_len.bind("<KeyRelease>", self.update_slider_from_entry)

        ctk.CTkButton(scroll_frame, text="GENERAR CONTRASEÑA", font=("Arial", 12, "bold"), height=35, 
                      command=self.action_generar).pack(fill="x", padx=20, pady=10)
        
        self.entry_res = ctk.CTkEntry(scroll_frame, justify="center", font=("Consolas", 16), height=55)
        self.entry_res.pack(fill="x", padx=20, pady=5)
        
        save_box = ctk.CTkFrame(scroll_frame, border_width=1, border_color="gray50")
        save_box.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(save_box, text="Guardar contraseña").pack(pady=(5,0))
        self.entry_site_name = ctk.CTkEntry(save_box, placeholder_text="Ej: Facebook, Banco, Correo...")
        self.entry_site_name.pack(fill="x", padx=10, pady=5)
        
        btn_row = ctk.CTkFrame(save_box, fg_color="transparent")
        btn_row.pack(pady=5)
        ctk.CTkButton(btn_row, text="Copiar", width=80, fg_color="gray", command=self.action_copiar).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="Guardar", width=120, command=self.action_guardar).pack(side="left", padx=5)
        self.lbl_status = ctk.CTkLabel(scroll_frame, text="")
        self.lbl_status.pack()

        # Evaluador
        ctk.CTkFrame(scroll_frame, height=2, fg_color="gray").pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(scroll_frame, text="AUDITOR DE FORTALEZA", font=("Arial", 12, "bold"), text_color="gray").pack(anchor="w", padx=10)
        
        self.entry_check_pass = ctk.CTkEntry(scroll_frame, placeholder_text="Pegar contraseña para auditar...", width=300, justify="center")
        self.entry_check_pass.pack(pady=5)
        self.entry_check_pass.bind("<KeyRelease>", self.action_evaluar_tiempo_real)
        
        self.prog_bar = ctk.CTkProgressBar(scroll_frame, width=300)
        self.prog_bar.pack(pady=10)
        self.prog_bar.set(0)
        
        self.lbl_eval_result = ctk.CTkLabel(scroll_frame, text="---", font=("Arial", 14, "bold"))
        self.lbl_eval_result.pack(pady=(0, 20))

    def setup_vault_tab(self):
        ctk.CTkButton(self.tab_vault, text="🔄 Actualizar Lista", height=25, fg_color="transparent", 
                      border_width=1, text_color=("gray10", "gray90"), command=self.refresh_vault).pack(pady=10)
        self.scroll_vault = ctk.CTkScrollableFrame(self.tab_vault)
        self.scroll_vault.pack(fill="both", expand=True, padx=5, pady=5)
        self.refresh_vault()

    def refresh_vault(self):
        for w in self.scroll_vault.winfo_children(): w.destroy()
        
        items = backend.get_vault_items()
        if not items:
            ctk.CTkLabel(self.scroll_vault, text="Aún no tienes contraseñas guardadas.").pack(pady=20)
            return

        for rid, site, pwd in items:
            card = ctk.CTkFrame(self.scroll_vault, fg_color=("gray85", "gray17"))
            card.pack(fill="x", pady=5, padx=5)
            
            initial = site[0].upper() if site else "#"
            ctk.CTkLabel(card, text=initial, font=("Arial Black", 18), width=40, height=40, 
                         fg_color="gray40", corner_radius=5).pack(side="left", padx=10, pady=10)
            
            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", fill="both", expand=True)
            ctk.CTkLabel(info, text=site, font=("Arial", 13, "bold"), anchor="w").pack(fill="x")
            ctk.CTkLabel(info, text="••••••••", text_color="gray", anchor="w").pack(fill="x")
            
            ctk.CTkButton(card, text="Copiar", width=60, height=25, command=lambda p=pwd: self.flash_copy(p)).pack(side="right", padx=10)
            ctk.CTkButton(card, text="✖", width=30, height=25, fg_color="#c62828", hover_color="#b71c1c", 
                          command=lambda i=rid: [backend.delete_vault_item(i), self.refresh_vault()]).pack(side="right", padx=(0, 5))

    def update_entry_from_slider(self, value):
        self.entry_len.delete(0, 'end')
        self.entry_len.insert(0, str(int(value)))

    def update_slider_from_entry(self, event):
        try:
            val = int(self.entry_len.get())
            if 4 <= val <= 100:
                self.slider.set(val)
        except ValueError:
            pass

    def action_generar(self):
        try:
            l = int(self.entry_len.get())
        except:
            l = 16
            
        vals = [v.get() for v in self.chk_vars]
        pwd = generar_contrasena(l, *vals)
        self.entry_res.delete(0, 'end')
        self.entry_res.insert(0, pwd)
        self.entry_check_pass.delete(0, 'end')
        self.entry_check_pass.insert(0, pwd)
        self.action_evaluar_tiempo_real()

    def action_copiar(self):
        pwd = self.entry_res.get()
        if pwd:
            pyperclip.copy(pwd)
            self.lbl_status.configure(text="¡Copiado!", text_color="#66bb6a")
            self.after(2000, lambda: self.lbl_status.configure(text=""))

    def action_guardar(self):
        site = self.entry_site_name.get()
        pwd = self.entry_res.get()
        if not site or not pwd:
            self.lbl_status.configure(text="Faltan datos", text_color="#ef5350")
            return
        
        if backend.save_password_to_vault(site, pwd):
            self.lbl_status.configure(text="¡Guardado!", text_color="#66bb6a")
            self.entry_site_name.delete(0, 'end')
            self.refresh_vault()
        else:
            self.lbl_status.configure(text="Error IO", text_color="#ef5350")

    def flash_copy(self, pwd):
        pyperclip.copy(pwd)

    def action_evaluar_tiempo_real(self, event=None):
        pwd = self.entry_check_pass.get()
        puntos, texto, color_hex = evaluar_fortaleza_logica(pwd)
        progreso = min(1.0, puntos / 160)
        self.prog_bar.set(progreso)
        self.prog_bar.configure(progress_color=color_hex)
        self.lbl_eval_result.configure(text=texto, text_color=color_hex)

if __name__ == "__main__":
    app = App()
    app.mainloop()