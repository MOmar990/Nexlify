import socket
import threading
import datetime
import os
import time
import base64
import random
import uuid
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
from pathlib import Path

DEFAULT_PORT = 9999
BUFFER_SIZE = 4096
LOG_DIR = ".darkwire_logs"
DEFAULT_TIMEOUT = 300
KEEPALIVE_INTERVAL = 30
DEBUG = False
MAX_FILES = 5
MAX_FILE_SIZE = 100 * 1024 * 1024

start_time = None
start_time_lock = threading.Lock()

CODENAMES = [
    "NeonSpecter", "VoidPulse", "ShadowCipher", "GhostWraith", "DuskRaven",
    "CrypticNomad", "ZeroTrace", "PhantomByte", "DarkViper", "SilentHex",
    "EclipseShade", "QuantumFang", "NexusDrift", "OblivionSpark"
]

BG_COLOR = "#1a1a1a"
FG_COLOR = "#d4a017"
ACCENT_COLOR = "#3a3a3a"

class PharaosEyesGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PHARAO'S EYES v4.0")
        self.root.geometry("1000x750")
        self.root.configure(bg=BG_COLOR)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.codename = None
        self.token = None
        self.passphrase = None
        self.sock = None
        self.client_sockets = []
        self.lock = threading.Lock()
        self.aes_key = None
        self.ghost_mode = False
        self.scramble_mode = None
        self.running = False
        self.stop_event = threading.Event()
        self.show_mode_dialog()

    def show_mode_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("DARKNET ENTRY")
        dialog.geometry("400x250")
        dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        tk.Label(dialog, text="☥ PHARAO'S EYES ☥", font=("Consolas", 18, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=15)
        tk.Label(dialog, text="SELECT ACCESS:", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=10)
        tk.Button(dialog, text="HOST NODE", command=lambda: self.show_host_dialog(dialog), bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(pady=10)
        tk.Button(dialog, text="JOIN NODE", command=lambda: self.show_join_dialog(dialog), bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(pady=10)

    def show_host_dialog(self, prev_dialog):
        prev_dialog.destroy()
        dialog = tk.Toplevel(self.root)
        dialog.title("CONFIGURE DARKNODE")
        dialog.geometry("500x400")
        dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        tk.Label(dialog, text="☥ NODE SETUP ☥", font=("Consolas", 18, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=15)
        tk.Label(dialog, text="Handle (or 'random'):", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        codename_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12))
        codename_entry.pack(pady=5)
        codename_entry.insert(0, "random")
        tk.Label(dialog, text="Keyphrase:", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        passphrase_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12), show="*")
        passphrase_entry.pack(pady=5)
        tk.Label(dialog, text=f"Port (default {DEFAULT_PORT}):", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        port_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12))
        port_entry.pack(pady=5)
        self.token = generate_token()
        tk.Label(dialog, text=f"DarkKey: {self.token}", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=15)
        tk.Label(dialog, text="Distribute to operatives!", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 10, "italic")).pack()
        def start_host():
            self.codename = codename_entry.get().strip() or generate_codename()
            self.passphrase = passphrase_entry.get().strip()
            port = port_entry.get().strip() or str(DEFAULT_PORT)
            if not self.passphrase:
                messagebox.showerror("Error", "Keyphrase required.")
                return
            self.start_host(int(port))
            dialog.destroy()
        tk.Button(dialog, text="DEPLOY", command=start_host, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(pady=20)

    def show_join_dialog(self, prev_dialog):
        prev_dialog.destroy()
        dialog = tk.Toplevel(self.root)
        dialog.title("INFILTRATE DARKNODE")
        dialog.geometry("500x500")
        dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        tk.Label(dialog, text="☥ INFILTRATION ☥", font=("Consolas", 18, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=15)
        tk.Label(dialog, text="Handle (or 'random'):", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        codename_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12))
        codename_entry.pack(pady=5)
        codename_entry.insert(0, "random")
        tk.Label(dialog, text="Keyphrase:", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        passphrase_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12), show="*")
        passphrase_entry.pack(pady=5)
        tk.Label(dialog, text="Node IP (default 127.0.0.1):", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        ip_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12))
        ip_entry.pack(pady=5)
        ip_entry.insert(0, "127.0.0.1")
        tk.Label(dialog, text=f"Port (default {DEFAULT_PORT}):", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        port_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12))
        port_entry.pack(pady=5)
        tk.Label(dialog, text="DarkKey (from host):", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 14)).pack(pady=5)
        token_entry = tk.Entry(dialog, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 12))
        token_entry.pack(pady=5)
        def start_join():
            self.codename = codename_entry.get().strip() or generate_codename()
            self.passphrase = passphrase_entry.get().strip()
            self.token = token_entry.get().strip()
            ip = ip_entry.get().strip() or "127.0.0.1"
            port = port_entry.get().strip() or str(DEFAULT_PORT)
            if not self.passphrase or not self.token:
                messagebox.showerror("Error", "Keyphrase and DarkKey required.")
                return
            self.connect_to_host(ip, int(port))
            dialog.destroy()
        tk.Button(dialog, text="INFILTRATE", command=start_join, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(pady=20)

    def build_gui(self):
        tk.Label(self.root, text="☥ PHARAO'S EYES v4.0 ☥", font=("Consolas", 18, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=15)
        status_frame = tk.Frame(self.root, bg=BG_COLOR, bd=2, relief=tk.RAISED)
        status_frame.pack(side=tk.LEFT, padx=15, pady=15, fill=tk.Y)
        tk.Label(status_frame, text="☥ DARKNET STATUS ☥", font=("Consolas", 14, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=10)
        self.status_label = tk.Label(status_frame, text=f"NODE: {'HOST' if self.client_sockets else 'OPERATIVE'}\nDARKKEY: {self.token[:8]}...\nHANDLE: {self.codename}\nOPERATIVES: {len(self.client_sockets) if self.client_sockets else 0}\nSTEALTH: {'ACTIVE' if self.ghost_mode else 'OFF'}\nCRYPT: {self.scramble_mode or 'OFF'}", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 12), justify=tk.LEFT)
        self.status_label.pack(pady=5)
        chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        chat_frame.pack(expand=True, fill=tk.BOTH, padx=15, pady=15)
        self.chat_text = tk.Text(chat_frame, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 14), wrap=tk.WORD, height=25, state=tk.DISABLED)
        self.chat_text.pack(expand=True, fill=tk.BOTH)
        scrollbar = ttk.Scrollbar(chat_frame, orient=tk.VERTICAL, command=self.chat_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.config(yscrollcommand=scrollbar.set)
        input_frame = tk.Frame(self.root, bg=BG_COLOR)
        input_frame.pack(fill=tk.X, padx=15, pady=15)
        self.input_entry = tk.Entry(input_frame, bg=ACCENT_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, font=("Consolas", 14))
        self.input_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.input_entry.bind("<Return>", lambda event: self.send_message())
        tk.Button(input_frame, text="TRANSMIT", command=self.send_message, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="WIPE", command=self.clear_chat, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="STEALTH", command=self.toggle_ghost, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="CRYPT", command=self.toggle_scramble, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        if self.client_sockets:
            tk.Button(input_frame, text="SCAN", command=self.who, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="PING", command=self.ping, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="SHARE", command=self.share_files, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="DISCONNECT", command=self.on_closing, bg=ACCENT_COLOR, fg=FG_COLOR, font=("Consolas", 12, "bold")).pack(side=tk.LEFT, padx=5)

    def log(self, message, is_sent=False):
        self.chat_text.config(state=tk.NORMAL)
        align = "w" if is_sent else "end"
        self.chat_text.insert(tk.END, message + "\n", ("sent" if is_sent else "received",))
        self.chat_text.tag_configure("sent", justify="left", lmargin1=10)
        self.chat_text.tag_configure("received", justify="right", rmargin=10)
        self.chat_text.insert(tk.END, "\n")
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def derive_key(self):
        return hashlib.sha256((self.passphrase + self.token).encode()).digest()

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ct_bytes

    def decrypt_message(self, ciphertext):
        try:
            iv = ciphertext[:16]
            ct = ciphertext[16:]
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode()
        except Exception:
            return "[!] DECRYPTION ERROR"

    def encrypt_file_chunk(self, chunk):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(chunk, AES.block_size))
        return cipher.iv + ct_bytes

    def decrypt_file_chunk(self, encrypted_chunk):
        try:
            iv = encrypted_chunk[:16]
            ct = encrypted_chunk[16:]
            if len(ct) < AES.block_size:
                return None
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
            decrypted_chunk = unpad(cipher.decrypt(ct), AES.block_size)
            return decrypted_chunk
        except Exception:
            return None

    def format_my_message(self, message):
        display_codename = hashlib.md5(self.codename.encode()).hexdigest()[:8] if self.ghost_mode else self.codename
        return f"{display_codename} [{self.timestamp()}]: {message}"

    def format_partner_message(self, codename, message):
        return f"{codename} [{self.timestamp()}]: {message}"

    def timestamp(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def send_message(self):
        message = self.input_entry.get().strip()
        if not message:
            return
        self.input_entry.delete(0, tk.END)
        if message.startswith("/"):
            self.handle_command(message)
            return
        if self.scramble_mode:
            message = base64.b64encode(message.encode()).decode()
        full_message = self.format_my_message(message)
        if self.sock:
            self.sock.send(self.encrypt_message(full_message))
            self.log(full_message, is_sent=True)
        elif self.client_sockets:
            with self.lock:
                for client_socket, _ in self.client_sockets[:]:
                    try:
                        client_socket.send(self.encrypt_message(full_message))
                    except:
                        self.client_sockets.remove((client_socket, _))
                        self.log(f"[*] OPERATIVE DROPPED")
                self.log(full_message, is_sent=True)
            self.update_status()

    def handle_command(self, message):
        global start_time
        if message == "/exit":
            self.on_closing()
        elif message == "/clear":
            self.clear_chat()
        elif message == "/status":
            role = "HOST" if self.client_sockets else "OPERATIVE"
            agents = len(self.client_sockets) if self.client_sockets else 0
            self.log(f"[*] STATUS: {role} | OPERATIVES: {agents} | STEALTH: {'ACTIVE' if self.ghost_mode else 'OFF'} | CRYPT: {self.scramble_mode or 'OFF'}")
        elif message == "/ghost":
            self.toggle_ghost()
        elif message == "/scramble":
            self.toggle_scramble()
        elif message == "/who" and self.client_sockets:
            with self.lock:
                agents = ", ".join([c[1] for c in self.client_sockets]) or "None"
                self.log(f"[*] ACTIVE OPERATIVES: {agents}")
        elif message == "/ping":
            with start_time_lock:
                start_time = time.time()
            if self.sock:
                self.sock.send(self.encrypt_message("/ping"))
            self.log("[*] PINGING DARKNET...")

    def toggle_ghost(self):
        self.ghost_mode = not self.ghost_mode
        self.log(f"[*] STEALTH {'ENABLED' if self.ghost_mode else 'DISABLED'}")
        self.update_status()

    def toggle_scramble(self):
        self.scramble_mode = "base64" if not self.scramble_mode else None
        self.log(f"[*] CRYPT {'ENABLED [BASE64]' if self.scramble_mode else 'DISABLED'}")
        self.update_status()

    def who(self):
        self.handle_command("/who")

    def ping(self):
        self.handle_command("/ping")

    def clear_chat(self):
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete(1.0, tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def update_status(self):
        role = "HOST" if self.client_sockets else "OPERATIVE"
        agents = len(self.client_sockets) if self.client_sockets else 0
        self.status_label.config(text=f"NODE: {role}\nDARKKEY: {self.token[:8]}...\nHANDLE: {self.codename}\nOPERATIVES: {agents}\nSTEALTH: {'ACTIVE' if self.ghost_mode else 'OFF'}\nCRYPT: {self.scramble_mode or 'OFF'}")

    def share_files(self):
        files = filedialog.askopenfilenames(title="Select Files to Share", filetypes=[("All files", "*.*")])
        if not files:
            return
        selected_files = list(files)[:MAX_FILES]
        valid_files = []
        for file_path in selected_files:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                self.log(f"[!] File {os.path.basename(file_path)} exceeds size limit ({MAX_FILE_SIZE // (1024 * 1024)} MB)")
                continue
            valid_files.append(file_path)
        if not valid_files:
            self.log("[!] No valid files selected.")
            return
        self.log(f"[*] Preparing to share {len(valid_files)} file(s)...")
        threading.Thread(target=self.send_files, args=(valid_files,), daemon=True).start()

    def send_files(self, file_paths):
        for file_path in file_paths:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            metadata = f"FILE:{file_name}:{file_size}"
            encrypted_metadata = self.encrypt_message(metadata)
            if self.sock:
                try:
                    self.sock.send(encrypted_metadata)
                except Exception as e:
                    self.log(f"[!] Failed to send metadata for {file_name}: {e}")
                    return
            elif self.client_sockets:
                with self.lock:
                    for client_socket, _ in self.client_sockets[:]:
                        try:
                            client_socket.send(encrypted_metadata)
                        except:
                            self.client_sockets.remove((client_socket, _))
                            self.log(f"[*] OPERATIVE DROPPED")
                    self.update_status()
            chunk_count = (file_size + BUFFER_SIZE - 1) // BUFFER_SIZE
            metadata_chunk_count = f"CHUNKS:{chunk_count}"
            encrypted_chunk_metadata = self.encrypt_message(metadata_chunk_count)
            if self.sock:
                try:
                    self.sock.send(encrypted_chunk_metadata)
                except Exception as e:
                    self.log(f"[!] Failed to send chunk metadata for {file_name}: {e}")
                    return
            elif self.client_sockets:
                with self.lock:
                    for client_socket, _ in self.client_sockets[:]:
                        try:
                            client_socket.send(encrypted_chunk_metadata)
                        except:
                            self.client_sockets.remove((client_socket, _))
                            self.log(f"[*] OPERATIVE DROPPED")
                    self.update_status()
            sent_chunks = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = self.encrypt_file_chunk(chunk)
                    if self.sock:
                        try:
                            self.sock.send(encrypted_chunk)
                            sent_chunks += 1
                        except Exception as e:
                            self.log(f"[!] Failed to send chunk {sent_chunks} for {file_name}: {e}")
                            return
                    elif self.client_sockets:
                        with self.lock:
                            for client_socket, _ in self.client_sockets[:]:
                                try:
                                    client_socket.send(encrypted_chunk)
                                except:
                                    self.client_sockets.remove((client_socket, _))
                                    self.log(f"[*] OPERATIVE DROPPED")
                            self.update_status()
                            sent_chunks += 1
            self.log(f"[*] Sent file: {file_name} ({file_size} bytes, {sent_chunks} chunks)")

    def receive_file(self, file_name, file_size, socket):
        def handle_file():
            try:
                chunk_metadata = socket.recv(BUFFER_SIZE)
                if not chunk_metadata:
                    self.log(f"[!] Failed to receive chunk metadata for {file_name}")
                    return
                decrypted_chunk_metadata = self.decrypt_message(chunk_metadata)
                if not decrypted_chunk_metadata.startswith("CHUNKS:"):
                    self.log(f"[!] Invalid chunk metadata for {file_name}")
                    return
                chunk_count = int(decrypted_chunk_metadata.split(":")[1])
            except Exception as e:
                self.log(f"[!] Failed to process chunk metadata for {file_name}: {e}")
                return
            save_path = filedialog.asksaveasfilename(
                title=f"Save File: {file_name}",
                initialfile=file_name,
                defaultextension=Path(file_name).suffix
            )
            if not save_path:
                self.log(f"[*] File {file_name} download canceled.")
                for _ in range(chunk_count):
                    try:
                        socket.recv(BUFFER_SIZE)
                    except:
                        break
                return
            received_chunks = 0
            received_bytes = 0
            with open(save_path, "wb") as f:
                while received_chunks < chunk_count:
                    try:
                        encrypted_chunk = socket.recv(BUFFER_SIZE)
                        if not encrypted_chunk:
                            self.log(f"[!] File {file_name} transfer interrupted at chunk {received_chunks}")
                            return
                        decrypted_chunk = self.decrypt_file_chunk(encrypted_chunk)
                        if decrypted_chunk is None:
                            self.log(f"[!] Failed to decrypt chunk {received_chunks} for {file_name}")
                            return
                        f.write(decrypted_chunk)
                        received_chunks += 1
                        received_bytes += len(decrypted_chunk)
                    except Exception as e:
                        self.log(f"[!] Failed to receive chunk {received_chunks} for {file_name}: {e}")
                        return
            if received_bytes >= file_size:
                self.log(f"[*] File saved: {file_name} ({received_bytes} bytes, {received_chunks} chunks)")
            else:
                self.log(f"[!] File {file_name} incomplete: {received_bytes}/{file_size} bytes, {received_chunks}/{chunk_count} chunks")
        response = messagebox.askyesno(
            "File Transfer",
            f"Receive file '{file_name}' ({file_size} bytes)?",
            parent=self.root
        )
        if response:
            threading.Thread(target=handle_file, daemon=True).start()
        else:
            self.log(f"[*] File {file_name} rejected.")
            try:
                chunk_metadata = socket.recv(BUFFER_SIZE)
                decrypted_chunk_metadata = self.decrypt_message(chunk_metadata)
                if decrypted_chunk_metadata.startswith("CHUNKS:"):
                    chunk_count = int(decrypted_chunk_metadata.split(":")[1])
                    for _ in range(chunk_count):
                        socket.recv(BUFFER_SIZE)
            except:
                pass

    def start_host(self, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(DEFAULT_TIMEOUT)
        try:
            self.server_socket.bind(("0.0.0.0", port))
            self.server_socket.listen(5)
            self.aes_key = self.derive_key()
            self.running = True
            self.build_gui()
            self.log(f"[*] DARKNODE ONLINE. DARKKEY: {self.token}\n[*] DISTRIBUTE DARKKEY AND KEYPHRASE TO OPERATIVES")
            threading.Thread(target=self.accept_clients, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Node bind failed: {e}")
            self.root.quit()

    def accept_clients(self):
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break

    def handle_client(self, client_socket, client_address):
        client_socket.settimeout(DEFAULT_TIMEOUT)
        client_codename = "UNKNOWN"
        try:
            data = client_socket.recv(BUFFER_SIZE)
            decrypted = self.decrypt_message(data)
            if decrypted.startswith("CODENAME:"):
                client_codename = decrypted[9:]
                with self.lock:
                    self.client_sockets.append((client_socket, client_codename))
                self.broadcast(f"[*] OPERATIVE {client_codename} INFILTRATED FROM {client_address[0]}", exclude=client_socket)
                self.log(f"[*] OPERATIVE {client_codename} INFILTRATED FROM {client_address[0]}")
                self.update_status()
            while self.running:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                decrypted = self.decrypt_message(data)
                if decrypted == "/exit":
                    break
                elif decrypted == "/ping":
                    client_socket.send(self.encrypt_message("/pong"))
                elif decrypted == "/who":
                    with self.lock:
                        agent_list = ", ".join([c[1] for c in self.client_sockets]) or "None"
                        self.broadcast(f"[*] ACTIVE OPERATIVES: {agent_list}")
                elif decrypted.startswith("FILE:"):
                    self.broadcast(decrypted, exclude=client_socket)
                    chunk_metadata = client_socket.recv(BUFFER_SIZE)
                    chunk_metadata_decrypted = self.decrypt_message(chunk_metadata)
                    if chunk_metadata_decrypted.startswith("CHUNKS:"):
                        self.broadcast_raw(chunk_metadata, exclude=client_socket)
                        chunk_count = int(chunk_metadata_decrypted.split(":")[1])
                        _, file_name, file_size = decrypted.split(":")
                        file_size = int(file_size)
                        for _ in range(chunk_count):
                            chunk = client_socket.recv(BUFFER_SIZE)
                            if not chunk:
                                break
                            self.broadcast_raw(chunk, exclude=client_socket)
                        self.log(f"[*] Forwarded file: {file_name} from {client_codename}")
                else:
                    formatted = self.format_partner_message(client_codename, decrypted.split(":", 1)[1].strip() if ":" in decrypted else decrypted)
                    self.log(formatted)
                    self.broadcast(formatted, exclude=client_socket)
        except Exception as e:
            self.log(f"[!] ERROR WITH OPERATIVE [{client_codename}]: {e}")
        finally:
            with self.lock:
                self.client_sockets[:] = [(s, c) for s, c in self.client_sockets if s != client_socket]
            self.log(f"[*] OPERATIVE {client_codename} DROPPED")
            self.broadcast(f"[*] OPERATIVE {client_codename} DROPPED")
            client_socket.close()
            self.update_status()

    def connect_to_host(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(DEFAULT_TIMEOUT)
        try:
            self.sock.connect((ip, port))
            self.aes_key = self.derive_key()
            self.sock.send(self.encrypt_message(f"CODENAME:{self.codename}"))
            self.running = True
            self.build_gui()
            self.log(f"[*] INFILTRATED NODE AT {ip} [DARKKEY:{self.token}]")
            threading.Thread(target=self.receive_messages, daemon=True).start()
            threading.Thread(target=self.keepalive_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Infiltration failed: {e}")
            self.root.quit()

    def keepalive_loop(self):
        while self.running:
            try:
                self.sock.send(self.encrypt_message("/keepalive"))
                time.sleep(KEEPALIVE_INTERVAL)
            except:
                break

    def receive_messages(self):
        while self.running:
            try:
                data = self.sock.recv(BUFFER_SIZE)
                if not data:
                    self.log("[!] NODE COLLAPSED")
                    break
                decrypted = self.decrypt_message(data)
                if decrypted == "/exit":
                    self.log("[!] NODE SHUTDOWN DETECTED")
                    break
                elif decrypted == "/pong":
                    with start_time_lock:
                        if start_time is not None:
                            latency = int((time.time() - start_time) * 1000)
                            self.log(f"[*] PING RESPONSE: {latency}ms")
                            start_time = None
                elif decrypted.startswith("FILE:"):
                    _, file_name, file_size = decrypted.split(":")
                    file_size = int(file_size)
                    self.log(f"[*] Incoming file: {file_name} ({file_size} bytes)")
                    self.receive_file(file_name, file_size, self.sock)
                elif decrypted.startswith("[*]"):
                    self.log(decrypted)
                else:
                    self.log(decrypted)
            except socket.timeout:
                self.log("[!] TIMEOUT: Node silent")
                break
            except Exception as e:
                self.log(f"[!] RECEPTION ERROR: {e}")
                break

    def broadcast(self, message, exclude=None):
        with self.lock:
            for client_socket, _ in self.client_sockets[:]:
                if client_socket != exclude:
                    try:
                        client_socket.send(self.encrypt_message(message))
                    except:
                        self.client_sockets.remove((client_socket, _))

    def broadcast_raw(self, data, exclude=None):
        with self.lock:
            for client_socket, _ in self.client_sockets[:]:
                if client_socket != exclude:
                    try:
                        client_socket.send(data)
                    except:
                        self.client_sockets.remove((client_socket, _))

    def on_closing(self):
        self.running = False
        self.stop_event.set()
        if self.sock:
            self.sock.send(self.encrypt_message("/exit"))
            self.sock.close()
        elif self.client_sockets:
            with self.lock:
                for client_socket, _ in self.client_sockets[:]:
                    client_socket.send(self.encrypt_message("/exit"))
                    client_socket.close()
                self.client_sockets.clear()
            self.server_socket.close()
        self.root.quit()

def generate_codename():
    return random.choice(CODENAMES)

def generate_token():
    return str(uuid.uuid4())[:13].replace("-", "")

if __name__ == "__main__":
    root = tk.Tk()
    app = PharaosEyesGUI(root)
    root.mainloop()