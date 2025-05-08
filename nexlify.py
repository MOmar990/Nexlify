import socket
import threading
import datetime
import time
import random
import uuid
import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
import hashlib
import zlib
import logging
import psutil
import os

class Config:
    DEFAULT_PORT = 9999
    BUFFER_SIZE = 8192
    LOG_DIR = "secure_node_logs"
    DEFAULT_TIMEOUT = 300
    KEEPALIVE_INTERVAL = 30
    PING_TIMEOUT = 10
    DEBUG_MODE = True  # Enable verbose logging for debugging
    CODENAMES = [
        "AlphaCore", "BetaStream", "GammaLock", "DeltaShield", "EpsilonWave",
        "ZetaFlux", "EtaGuard", "ThetaSpark", "IotaPulse", "KappaVault"
    ]
    # Cyberpunk-inspired color palette for a sleek, professional look
    BG_COLOR = "#0D1117"  # Deep charcoal for a futuristic vibe
    FG_COLOR = "#C9D1D9"  # Light gray for readable text
    ACCENT_COLOR = "#00F5E1"  # Neon cyan for highlights
    SECONDARY_ACCENT = "#FF2E88"  # Neon magenta for secondary highlights
    PANEL_BG = "#161B22"  # Slightly lighter panel background
    STATUS_PANEL_BG = "#0A0E14"  # Darker for status panel
    BUTTON_HOVER_BG = "#1C2526"  # Subtle hover effect
    FONT_FAMILY = "JetBrains Mono"  # Modern monospaced font
    FONT_SIZE = 11  # Compact for a clean look
    BORDER_RADIUS = 8  # Rounded corners for softness
    SHADOW_COLOR = "#1C2526"  # Dark gray for shadow effect (Tkinter-compatible)

class CryptoEngine:
    def __init__(self, passphrase, token):
        self.passphrase = passphrase
        self.token = token
        self.key = self._derive_key()
        self.compress_mode = False

    def _derive_key(self):
        # Yo, we're cooking up a spicy 256-bit key with some passphrase and token magic!
        return hashlib.sha256((self.passphrase + self.token).encode()).digest()

    def encrypt(self, data, compress=False):
        # Encryption time! Turning your message into a secret code, optionally squishing it first.
        payload = data.encode()
        effective_compress = compress or self.compress_mode
        if effective_compress:
            payload = zlib.compress(payload)
        
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        compression_flag = b'\x01' if effective_compress else b'\x00'
        return compression_flag + cipher.nonce + tag + ciphertext

    def decrypt(self, data):
        # Decrypting the secret message! Let's hope it doesn't explode...
        try:
            compression_flag = data[0:1]
            nonce = data[1:17]
            tag = data[17:33]
            ciphertext = data[33:]
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)

            if compression_flag == b'\x01':
                return zlib.decompress(plaintext_bytes).decode()
            else:
                return plaintext_bytes.decode()
        except zlib.error as ze:
            logging.error(f"Zlib decompression failed: {ze}. Data length: {len(plaintext_bytes if 'plaintext_bytes' in locals() else data)}")
            return "[!] DECOMPRESSION ERROR (zlib)"
        except Exception as e:
            logging.error(f"Decryption failed: {e}. Data length: {len(data)}")
            return "[!] DECRYPTION ERROR"

    def generate_handshake(self):
        # Handshake hash: like a secret wink to make sure we're cool with each other.
        return hashlib.sha256((self.passphrase + self.token + "DarkWireHandshakeV2").encode()).hexdigest()

class NetworkManager:
    def __init__(self, config, crypto_engine, on_message, on_status_update):
        self.config = config
        self.crypto_engine = crypto_engine 
        self.on_message = on_message
        self.on_status_update = on_status_update
        self.sock = None
        self.server_socket = None
        self.client_sockets = []
        self.lock = threading.Lock()
        self.running = False
        self.stop_event = threading.Event()
        self.ip = None
        self.port = None
        self.host_codename = "Host"

    def check_port(self, port_to_check):
        # Checking if the port is free, because nobody likes a gatecrasher!
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port_to_check and conn.status == psutil.CONN_LISTEN:
                return False
        return True

    def start_host(self, port, host_codename):
        # Starting the host party! Let's make sure the port is free and get this show on the road.
        if not self.check_port(port):
            alternative_ports = [port + i for i in range(1, 5) if self.check_port(port + i)]
            port_suggestion = f"Try alternative ports: {', '.join(map(str, alternative_ports))}" if alternative_ports else "Close conflicting apps or pick another port."
            raise OSError(f"Port {port} is already in use. {port_suggestion}")
        
        self.host_codename = host_codename 
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(("0.0.0.0", port))
            self.server_socket.listen(5)
            self.running = True
            self.stop_event.clear()
            threading.Thread(target=self._accept_clients, daemon=True).start()
            self.on_message(f"[*] Secure node '{host_codename}' online on port {port}. Share the token and passphrase!")
            self.on_status_update() 
        except OSError as e:
            self.on_message(f"[!] Failed to initialize node: {e}")
            if self.server_socket: self.server_socket.close()
            self.server_socket = None
            self.on_status_update()
            raise

    def _accept_clients(self):
        # Welcoming new clients like a friendly bouncer at the club.
        while self.running and not self.stop_event.is_set():
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                self.server_socket.settimeout(None)
                threading.Thread(target=self._handle_client, args=(client_socket, client_address), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running and not self.stop_event.is_set(): 
                    self.on_message(f"[!] Error accepting clients: {e}")
                break

    def _handle_client(self, client_socket, client_address):
        # Handling each client like a VIP, but first, let's check their ID (handshake).
        client_socket.settimeout(self.config.DEFAULT_TIMEOUT)
        client_codename = "UNKNOWN" 
        try:
            if not self._verify_handshake(client_socket):
                self.on_message(f"[!] Unauthorized client at {client_address[0]}. Handshake failed.")
                client_socket.close()
                return

            self.on_message(f"[*] Handshake cool with {client_address[0]}. Waiting for their codename...")
            
            data = client_socket.recv(self.config.BUFFER_SIZE)
            if not data: 
                self.on_message(f"[!] Client {client_address[0]} bailed before sending codename.")
                client_socket.close()
                return

            decrypted = self.crypto_engine.decrypt(data)
            self.on_message(f"[*] Got packet from {client_address[0]}: '{decrypted}'") 

            if decrypted.startswith("CODENAME:"):
                client_codename = decrypted[9:].strip() 
                if not client_codename: 
                    self.on_message(f"[!] Empty codename from {client_address[0]}. Giving them a temp ID.")
                    client_codename = f"Client_{client_address[0]}" 
                
                self.on_message(f"[*] Codename '{client_codename}' from {client_address[0]} is legit!")
                with self.lock:
                    self.client_sockets.append((client_socket, client_codename))
                
                self._broadcast(f"[*] Network update: Client '{client_codename}' has joined the party.", exclude=client_socket)
                self.on_message(f"[*] Client '{client_codename}' ({client_address[0]}) is fully connected.")
                self.on_status_update()
            else:
                self.on_message(f"[!] Weird data from {client_address[0]}: '{decrypted}'. Kicking them out.")
                client_socket.close()
                return 

            while self.running and not self.stop_event.is_set():
                data = client_socket.recv(self.config.BUFFER_SIZE)
                if not data: break
                
                decrypted = self.crypto_engine.decrypt(data)
                if decrypted == "/exit": break
                elif decrypted == "/ping":
                    client_socket.send(self.crypto_engine.encrypt("/pong"))
                elif decrypted == "/who":
                    with self.lock:
                        agents = ", ".join(c[1] for c in self.client_sockets if c[1] != client_codename) 
                        active_clients_msg = f"[*] You are '{client_codename}'. Other agents: {agents if agents else 'None'}."
                    client_socket.send(self.crypto_engine.encrypt(active_clients_msg))
                else:
                    self.on_message(decrypted)
                    self._broadcast(decrypted, exclude=client_socket)
        
        except socket.timeout:
            self.on_message(f"[!] Client '{client_codename}' ({client_address[0]}) timed out. Snooze, you lose!")
        except ConnectionResetError:
            self.on_message(f"[!] Client '{client_codename}' ({client_address[0]}) yanked the plug!")
        except Exception as e:
            if self.running and not self.stop_event.is_set():
                 self.on_message(f"[!] Oops with client '{client_codename}' ({client_address[0]}): {type(e).__name__} - {e}")
        finally:
            disconnected_info = f"[*] Client '{client_codename}' ({client_address[0]}) left the chat."
            client_was_in_list = False
            with self.lock:
                for i, (s, _) in enumerate(self.client_sockets):
                    if s == client_socket:
                        self.client_sockets.pop(i)
                        client_was_in_list = True
                        break
            
            if client_was_in_list:
                self._broadcast(disconnected_info) 
                self.on_status_update() 
            else:
                disconnected_info = f"[*] Connection attempt from {client_address[0]} fizzled out."
            self.on_message(disconnected_info) 
            client_socket.close()

    def connect_to_host(self, ip, port, codename, max_retries=3):
        # Client mode: trying to join the host's cool party with retries.
        self.ip = ip
        self.port = port
        for attempt in range(max_retries):
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.config.PING_TIMEOUT)
                self.sock.connect((ip, port))
                self.sock.settimeout(self.config.DEFAULT_TIMEOUT)

                handshake_payload = self.crypto_engine.generate_handshake()
                self.sock.send(self.crypto_engine.encrypt(f"HANDSHAKE:{handshake_payload}"))
                if self.config.DEBUG_MODE:
                    logging.info(f"Sent handshake to {ip}:{port}")
                
                self.sock.send(self.crypto_engine.encrypt(f"CODENAME:{codename}"))
                if self.config.DEBUG_MODE:
                    logging.info(f"Sent codename '{codename}' to {ip}:{port}")
                
                self.running = True
                self.stop_event.clear()
                self.on_message(f"[*] Connected to node at {ip}:{port} as '{codename}'")
                threading.Thread(target=self._receive_messages, daemon=True).start()
                threading.Thread(target=self._keepalive_loop, daemon=True).start()
                self.on_status_update()
                return True
            except Exception as e:
                self.on_message(f"[!] Attempt {attempt + 1} to {ip}:{port} failed: {type(e).__name__} - {e}")
                if self.sock: self.sock.close(); self.sock = None
                time.sleep(2)
        self.on_message(f"[!] Failed to connect after {max_retries} tries. Sad trombone!")
        self.on_status_update()
        return False

    def _verify_handshake(self, sock):
        # Making sure the client's handshake isn't a fake mustache.
        try:
            sock.settimeout(self.config.PING_TIMEOUT)
            data = sock.recv(self.config.BUFFER_SIZE)
            sock.settimeout(self.config.DEFAULT_TIMEOUT)
            if not data: return False

            decrypted = self.crypto_engine.decrypt(data)
            if self.config.DEBUG_MODE:
                logging.info(f"Received handshake data: {decrypted[:20]}...")
            if not decrypted.startswith("HANDSHAKE:"):
                self.on_message(f"[!] Handshake format error: {decrypted}")
                return False
            
            client_hash = decrypted[10:]
            expected_hash = self.crypto_engine.generate_handshake()
            if client_hash == expected_hash:
                return True
            else:
                self.on_message(f"[!] Handshake hash mismatch. Expected: {expected_hash[:10]}..., Got: {client_hash[:10]}...")
                return False
        except socket.timeout:
            self.on_message("[!] Handshake timeout. Too slow, buddy!")
            return False
        except Exception as e:
            self.on_message(f"[!] Handshake error: {e}")
            return False

    def _receive_messages(self):
        # Client's ear on, listening for messages from the host.
        global start_time
        while self.running and not self.stop_event.is_set():
            try:
                data = self.sock.recv(self.config.BUFFER_SIZE)
                if not data:
                    self.on_message("[!] Node disconnected (no data)")
                    break
                
                decrypted = self.crypto_engine.decrypt(data)
                if self.config.DEBUG_MODE:
                    logging.info(f"Received message: {decrypted[:50]}...")
                if decrypted == "/exit":
                    self.on_message("[!] Node shutdown detected")
                    break
                elif decrypted == "/pong":
                    with start_time_lock:
                        if start_time is not None:
                            latency = int((time.time() - start_time) * 1000)
                            self.on_message(f"[*] Ping response: {latency}ms")
                            start_time = None
                else:
                    self.on_message(decrypted)
                
                with start_time_lock:
                    if start_time is not None and time.time() - start_time > self.config.PING_TIMEOUT:
                        self.on_message("[!] Ping timeout: Node's napping!")
                        start_time = None
            except socket.timeout:
                continue
            except ConnectionAbortedError:
                self.on_message("[!] Host kicked us out!")
                break
            except Exception as e:
                if self.running and not self.stop_event.is_set():
                    self.on_message(f"[!] Reception error: {type(e).__name__} - {e}")
                break
        
        self.running = False 
        if self.sock: self.sock.close(); self.sock = None
        self.on_status_update()

    def _keepalive_loop(self):
        # Client's heartbeat, pinging the host to say "I'm still here!"
        while self.running and not self.stop_event.is_set():
            for _ in range(self.config.KEEPALIVE_INTERVAL): 
                if not self.running or self.stop_event.is_set(): return
                time.sleep(1)

            if self.sock and self.running: 
                try:
                    self.sock.send(self.crypto_engine.encrypt("/keepalive"))
                    if self.config.DEBUG_MODE:
                        logging.info("Sent keepalive ping")
                except Exception as e:
                    self.on_message(f"[!] Keepalive failed: {e}. Disconnecting.")
                    self.running = False 
                    if self.sock: self.sock.close(); self.sock = None
                    self.on_status_update() 
                    break 

    def send_message(self, message_text, sender_codename, is_ghost_mode):
        # Sending a message, either to the host or broadcasting as the host. Ghost mode makes you sneaky!
        display_name = hashlib.sha256(sender_codename.encode()).hexdigest()[:8] if is_ghost_mode else sender_codename
        full_message_to_send = f"{display_name}: {message_text}"
        
        if self.sock:
            try:
                self.sock.send(self.crypto_engine.encrypt(full_message_to_send))
                if self.config.DEBUG_MODE:
                    logging.info(f"Sent message as client: {full_message_to_send[:50]}...")
                return full_message_to_send
            except Exception as e:
                self.on_message(f"[!] Failed to send message: {e}")
                logging.error(f"Send message failed: {e}")
                return None
        elif self.server_socket and self.client_sockets:
            try:
                host_display_name = hashlib.sha256(self.host_codename.encode()).hexdigest()[:8] if is_ghost_mode else self.host_codename
                message_for_host_log_and_broadcast = f"{host_display_name}: {message_text}"
                
                self._broadcast(message_for_host_log_and_broadcast)
                if self.config.DEBUG_MODE:
                    logging.info(f"Broadcast message as host: {message_for_host_log_and_broadcast[:50]}...")
                return message_for_host_log_and_broadcast 
            except Exception as e:
                self.on_message(f"[!] Failed to broadcast message: {e}")
                logging.error(f"Broadcast message failed: {e}")
                return None
        else:
            self.on_message("[!] Cannot send: No active connection or clients.")
            logging.warning("Send attempted with no active connection or clients")
        return None

    def _broadcast(self, message_to_broadcast, exclude=None):
        # Sending the message to all clients, like shouting in a crowded room (except one guy if excluded).
        encrypted_message = self.crypto_engine.encrypt(message_to_broadcast)
        self._broadcast_raw(encrypted_message, exclude)

    def _broadcast_raw(self, raw_data, exclude=None):
        # Broadcasting raw encrypted data. If someone doesn't answer, they're out!
        disconnected_clients = []
        with self.lock:
            for client_socket, client_name in self.client_sockets[:]: 
                if client_socket != exclude:
                    try:
                        client_socket.sendall(raw_data)
                        if self.config.DEBUG_MODE:
                            logging.info(f"Sent broadcast to {client_name}")
                    except Exception as e:
                        logging.warning(f"Error broadcasting to {client_name}: {e}. Marking for removal.")
                        disconnected_clients.append((client_socket, client_name))
        
        if disconnected_clients:
            with self.lock:
                for sock, name in disconnected_clients:
                    if (sock, name) in self.client_sockets:
                        self.client_sockets.remove((sock, name))
                        self.on_message(f"[*] Client {name} removed due to broadcast error.")
                        try: sock.close()
                        except: pass
            self.on_status_update()

    def shutdown(self):
        # Shutting down the party. Everyone out, lights off!
        self.on_message("[*] Initiating shutdown sequence...")
        self.running = False
        self.stop_event.set()

        if self.sock: 
            try:
                self.sock.send(self.crypto_engine.encrypt("/exit"))
            except: pass 
            finally:
                try: self.sock.shutdown(socket.SHUT_RDWR)
                except: pass
                self.sock.close()
                self.sock = None
        
        if self.server_socket: 
            with self.lock:
                for client_sock, client_name in self.client_sockets:
                    try:
                        self.on_message(f"[*] Closing connection to {client_name}...")
                        client_sock.send(self.crypto_engine.encrypt("/exit"))
                    except: pass
                    finally:
                        try: client_sock.shutdown(socket.SHUT_RDWR)
                        except: pass
                        client_sock.close()
                self.client_sockets.clear()
            
            try:
                self.on_message("[*] Closing server socket...")
                self.server_socket.close()
            except: pass
            finally:
                self.server_socket = None
        
        self.on_message("[*] Shutdown complete.")
        self.on_status_update()

class GUIManager:
    def __init__(self, root, config, network_manager):
        self.root = root
        self.config = config
        self.network_manager = network_manager
        self.codename = None
        self.token = None
        self.passphrase = None
        self.ghost_mode = False
        self.chat_text = None
        self.status_label = None
        self.title_label = None
        self.stealth_button = None
        self.compress_button = None
        self.token_display_var = None

        self.setup_logging()
        self.setup_root_window()
        self.show_mode_selection_dialog()

    def setup_logging(self):
        # Setting up the log file, because we need to keep track of all the juicy details!
        os.makedirs(self.config.LOG_DIR, exist_ok=True)
        log_file = os.path.join(self.config.LOG_DIR, f"darkwire_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        logging.basicConfig(filename=log_file, level=logging.DEBUG if self.config.DEBUG_MODE else logging.INFO, 
                           format="%(asctime)s - %(levelname)s - %(message)s")
        logging.info("DarkWire GUI Initialized.")

    def setup_root_window(self):
        # Making the main window look sleek and ready for action.
        self.root.title("DarkWire Node")
        self.root.geometry("1100x800")  # Slightly larger for a spacious feel
        self.root.configure(bg=self.config.BG_COLOR)
        self.root.protocol("WM_DELETE_WINDOW", self.handle_window_close_event)
        # Add a subtle shadow effect to the window
        self.root.wm_attributes("-alpha", 0.98)

    def show_mode_selection_dialog(self):
        # First screen: Are you the boss (host) or joining the fun (client)?
        for widget in self.root.winfo_children(): widget.destroy()
        self.root.title("DarkWire Node - Select Mode")

        mode_dialog_frame = tk.Frame(self.root, bg=self.config.BG_COLOR, highlightbackground=self.config.SHADOW_COLOR, highlightthickness=2)
        mode_dialog_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        tk.Label(mode_dialog_frame, text="DARKWIRE NODE", font=(self.config.FONT_FAMILY, 24, "bold"), bg=self.config.BG_COLOR, fg=self.config.ACCENT_COLOR).pack(pady=(60,30))
        tk.Label(mode_dialog_frame, text="Select Operational Mode:", bg=self.config.BG_COLOR, fg=self.config.FG_COLOR, font=(self.config.FONT_FAMILY, self.config.FONT_SIZE+1)).pack(pady=20)
        
        def button_style(btn):
            btn.config(bg=self.config.ACCENT_COLOR, fg=self.config.BG_COLOR, font=(self.config.FONT_FAMILY, self.config.FONT_SIZE+1, "bold"), 
                       relief=tk.FLAT, bd=0, highlightthickness=0, width=28, height=2)
            btn.bind("<Enter>", lambda e: btn.config(bg=self.config.BUTTON_HOVER_BG))
            btn.bind("<Leave>", lambda e: btn.config(bg=self.config.ACCENT_COLOR))

        host_btn = tk.Button(mode_dialog_frame, text="Initialize Node (Host)", command=self.show_host_config_dialog)
        button_style(host_btn)
        host_btn.pack(pady=15)
        
        client_btn = tk.Button(mode_dialog_frame, text="Connect to Node (Client)", command=self.show_client_connect_dialog)
        button_style(client_btn)
        client_btn.pack(pady=15)

    def _create_dialog_frame(self, title_text):
        # Helper to whip up a nice dialog frame for configs.
        for widget in self.root.winfo_children(): widget.destroy()
        
        dialog_frame = tk.Frame(self.root, bg=self.config.BG_COLOR, highlightbackground=self.config.SHADOW_COLOR, highlightthickness=2)
        dialog_frame.pack(expand=True, fill=tk.BOTH, padx=30, pady=30)
        
        tk.Label(dialog_frame, text=title_text, font=(self.config.FONT_FAMILY, 20, "bold"), bg=self.config.BG_COLOR, fg=self.config.ACCENT_COLOR).pack(pady=(20, 30))
        return dialog_frame

    def _add_entry_field(self, parent, label_text, show_char=None, default_text=None, width=40):
        # Quick helper to add a text box with a label. Easy peasy!
        frame = tk.Frame(parent, bg=self.config.BG_COLOR)
        frame.pack(pady=10, fill=tk.X)
        
        tk.Label(frame, text=label_text, bg=self.config.BG_COLOR, fg=self.config.FG_COLOR, font=(self.config.FONT_FAMILY, self.config.FONT_SIZE)).pack(anchor='w', pady=(0,2))
        entry = tk.Entry(frame, bg=self.config.PANEL_BG, fg=self.config.FG_COLOR, show=show_char, insertbackground=self.config.SECONDARY_ACCENT, 
                         font=(self.config.FONT_FAMILY, self.config.FONT_SIZE), relief=tk.FLAT, highlightthickness=1, highlightbackground=self.config.ACCENT_COLOR)
        entry.pack(fill=tk.X, ipady=5)
        if default_text:
            entry.insert(0, default_text)
        return entry

    def show_host_config_dialog(self):
        # Host setup screen: Pick your codename, passphrase, and port.
        dialog_frame = self._create_dialog_frame("HOST CONFIGURATION")
        
        codename_entry = self._add_entry_field(dialog_frame, "Your Codename (or 'random'):", default_text="random")
        passphrase_entry = self._add_entry_field(dialog_frame, "Connection Passphrase (share this):", show_char="*")
        port_entry = self._add_entry_field(dialog_frame, f"Port (default {self.config.DEFAULT_PORT}, share this):", default_text=str(self.config.DEFAULT_PORT))
        
        self.token = str(uuid.uuid4())[:13].replace("-", "").upper()
        
        tk.Label(dialog_frame, text="Authentication Token (share this):", bg=self.config.BG_COLOR, fg=self.config.FG_COLOR, font=(self.config.FONT_FAMILY, self.config.FONT_SIZE)).pack(pady=(20,5))
        token_frame = tk.Frame(dialog_frame, bg=self.config.BG_COLOR)
        token_frame.pack(pady=(0,15), padx=20, fill=tk.X)
        
        self.token_display_var = tk.StringVar(master=dialog_frame, value=self.token)
        token_entry_widget = tk.Entry(token_frame, textvariable=self.token_display_var, state='readonly', 
                                     readonlybackground=self.config.PANEL_BG, fg=self.config.ACCENT_COLOR, 
                                     relief=tk.FLAT, highlightthickness=1, highlightbackground=self.config.ACCENT_COLOR,
                                     justify='center', font=(self.config.FONT_FAMILY, self.config.FONT_SIZE+1, "bold"))
        token_entry_widget.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=5, padx=(0,5))

        def _copy_token_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.token_display_var.get())
            self.root.update() 
            messagebox.showinfo("Token Copied", "Authentication token copied to clipboard.", parent=self.root)

        copy_button = tk.Button(token_frame, text="Copy", command=_copy_token_to_clipboard, 
                                bg=self.config.SECONDARY_ACCENT, fg=self.config.BG_COLOR, relief=tk.FLAT, 
                                font=(self.config.FONT_FAMILY, self.config.FONT_SIZE), highlightthickness=0, width=6)
        copy_button.pack(side=tk.LEFT)
        copy_button.bind("<Enter>", lambda e: copy_button.config(bg=self.config.BUTTON_HOVER_BG))
        copy_button.bind("<Leave>", lambda e: copy_button.config(bg=self.config.SECONDARY_ACCENT))
        
        tk.Label(dialog_frame, text="Important: Share Passphrase, Port, and Token with clients.", 
                 bg=self.config.BG_COLOR, fg=self.config.FG_COLOR, 
                 font=(self.config.FONT_FAMILY, self.config.FONT_SIZE-1, "italic"), wraplength=500).pack(pady=(10,20))

        button_frame = tk.Frame(dialog_frame, bg=self.config.BG_COLOR)
        button_frame.pack(pady=20)

        def start_host_action_ui():
            # Let's fire up the host, but only if the inputs make sense!
            self.codename = codename_entry.get().strip()
            if not self.codename or self.codename.lower() == 'random':
                 self.codename = random.choice(self.config.CODENAMES)
            self.passphrase = passphrase_entry.get().strip()
            port_str = port_entry.get().strip()
            
            if not self.passphrase:
                messagebox.showerror("Error", "Passphrase is required.", parent=self.root)
                return
            try:
                port = int(port_str) if port_str else self.config.DEFAULT_PORT
                if not (1024 <= port <= 65535):
                    messagebox.showerror("Error", "Port must be between 1024 and 65535.", parent=self.root)
                    return
            except ValueError:
                messagebox.showerror("Error", "Invalid port number.", parent=self.root)
                return
            
            crypto = CryptoEngine(self.passphrase, self.token)
            self.network_manager.crypto_engine = crypto
            
            try:
                self.network_manager.start_host(port, self.codename) 
                self.build_main_chat_gui()
            except Exception as e:
                messagebox.showerror("Node Error", f"Node initialization failed: {e}", parent=self.root)

        deploy_btn = tk.Button(button_frame, text="Deploy Node", command=start_host_action_ui, 
                               bg=self.config.ACCENT_COLOR, fg=self.config.BG_COLOR, 
                               font=(self.config.FONT_FAMILY, self.config.FONT_SIZE+1, "bold"), relief=tk.FLAT, width=15, height=2)
        deploy_btn.pack(side=tk.LEFT, padx=10)
        deploy_btn.bind("<Enter>", lambda e: deploy_btn.config(bg=self.config.BUTTON_HOVER_BG))
        deploy_btn.bind("<Leave>", lambda e: deploy_btn.config(bg=self.config.ACCENT_COLOR))

        back_btn = tk.Button(button_frame, text="Back", command=self.show_mode_selection_dialog, 
                             bg=self.config.PANEL_BG, fg=self.config.FG_COLOR, 
                             font=(self.config.FONT_FAMILY, self.config.FONT_SIZE), relief=tk.FLAT, width=10, height=2)
        back_btn.pack(side=tk.LEFT, padx=10)
        back_btn.bind("<Enter>", lambda e: back_btn.config(bg=self.config.BUTTON_HOVER_BG))
        back_btn.bind("<Leave>", lambda e: back_btn.config(bg=self.config.PANEL_BG))

    def show_client_connect_dialog(self):
        # Client setup screen: Enter the host's details to join the party.
        dialog_frame = self._create_dialog_frame("CLIENT CONNECTION")

        codename_entry = self._add_entry_field(dialog_frame, "Your Codename (or 'random'):", default_text="random")
        passphrase_entry = self._add_entry_field(dialog_frame, "Host's Passphrase:", show_char="*")
        ip_entry = self._add_entry_field(dialog_frame, "Host's IP Address (e.g., 127.0.0.1):", default_text="127.0.0.1")
        port_entry = self._add_entry_field(dialog_frame, f"Host's Port (e.g., {self.config.DEFAULT_PORT}):", default_text=str(self.config.DEFAULT_PORT))
        token_entry = self._add_entry_field(dialog_frame, "Host's Authentication Token:")

        button_frame = tk.Frame(dialog_frame, bg=self.config.BG_COLOR)
        button_frame.pack(pady=30)
        
        connect_button = tk.Button(button_frame, text="Connect to Node", 
                                  bg=self.config.ACCENT_COLOR, fg=self.config.BG_COLOR, 
                                  font=(self.config.FONT_FAMILY, self.config.FONT_SIZE+1, "bold"), relief=tk.FLAT, width=18, height=2)
        connect_button.pack(side=tk.LEFT, padx=10)
        connect_button.bind("<Enter>", lambda e: connect_button.config(bg=self.config.BUTTON_HOVER_BG))
        connect_button.bind("<Leave>", lambda e: connect_button.config(bg=self.config.ACCENT_COLOR))

        back_btn = tk.Button(button_frame, text="Back", command=self.show_mode_selection_dialog, 
                             bg=self.config.PANEL_BG, fg=self.config.FG_COLOR, 
                             font=(self.config.FONT_FAMILY, self.config.FONT_SIZE), relief=tk.FLAT, width=10, height=2)
        back_btn.pack(side=tk.LEFT, padx=10)
        back_btn.bind("<Enter>", lambda e: back_btn.config(bg=self.config.BUTTON_HOVER_BG))
        back_btn.bind("<Leave>", lambda e: back_btn.config(bg=self.config.PANEL_BG))

        def start_connect_action_ui():
            self.codename = codename_entry.get().strip()
            if not self.codename or self.codename.lower() == 'random':
                self.codename = random.choice(self.config.CODENAMES)
            self.passphrase = passphrase_entry.get().strip()
            self.token = token_entry.get().strip().upper()
            ip = ip_entry.get().strip() or "127.0.0.1"
            port_str = port_entry.get().strip()

            if not self.passphrase or not self.token:
                messagebox.showerror("Error", "Passphrase and Auth Token are required.", parent=self.root)
                return
            try:
                port = int(port_str) if port_str else self.config.DEFAULT_PORT
                if not (1024 <= port <= 65535):
                    messagebox.showerror("Error", "Port must be between 1024 and 65535.", parent=self.root)
                    return
            except ValueError:
                messagebox.showerror("Error", "Invalid port number.", parent=self.root)
                return

            if not self.validate_ip(ip): 
                messagebox.showerror("Error", "Invalid IP address format.", parent=self.root)
                return
            
            crypto = CryptoEngine(self.passphrase, self.token)
            self.network_manager.crypto_engine = crypto
            
            connect_button.config(text="Connecting...", state=tk.DISABLED)
            if dialog_frame.winfo_exists(): dialog_frame.update_idletasks() 
            
            threading.Thread(target=self._connect_thread_target_ui, args=(ip, port, self.codename, connect_button), daemon=True).start()

        connect_button.config(command=start_connect_action_ui)

    def _connect_thread_target_ui(self, ip, port, codename, connect_button):
        # Attempting to join the host's party in a separate thread to keep the GUI responsive!
        try:
            success = self.network_manager.connect_to_host(ip, port, codename)
            if success:
                self.root.after(0, self.build_main_chat_gui)
            else:
                self.root.after(0, lambda: messagebox.showerror("Connection Failed", "Failed to connect to the node.", parent=self.root))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Connection Error", f"Connection failed: {e}", parent=self.root))
        finally:
            if connect_button.winfo_exists():
                self.root.after(0, lambda: connect_button.config(text="Connect to Node", state=tk.NORMAL))

    def validate_ip(self, ip_str):
        # Making sure the IP address isn't some gibberish.
        try:
            socket.inet_aton(ip_str) 
            return True
        except socket.error:
            return False

    def build_main_chat_gui(self):
        # Building the chat room! Time to make it look cool and functional.
        for widget in self.root.winfo_children(): widget.destroy()
        
        self.root.title(f"DarkWire Node - {self.codename} ({'Host' if self.network_manager.server_socket else 'Client'})")

        top_frame = tk.Frame(self.root, bg=self.config.BG_COLOR)
        top_frame.pack(fill=tk.X, pady=(10,5))
        tk.Label(top_frame, text=f"DARKWIRE NODE", font=(self.config.FONT_FAMILY, 20, "bold"), bg=self.config.BG_COLOR, fg=self.config.ACCENT_COLOR).pack(pady=5)
        self.title_label = tk.Label(top_frame, text=f"Mode: {'Host' if self.network_manager.server_socket else 'Client'} | Codename: {self.codename}", 
                                    font=(self.config.FONT_FAMILY, self.config.FONT_SIZE), bg=self.config.BG_COLOR, fg=self.config.FG_COLOR)
        self.title_label.pack(pady=5)

        content_frame = tk.Frame(self.root, bg=self.config.BG_COLOR)
        content_frame.pack(expand=True, fill=tk.BOTH, padx=15, pady=(0,10))

        status_panel = tk.Frame(content_frame, bg=self.config.STATUS_PANEL_BG, width=250, relief=tk.FLAT, 
                                highlightbackground=self.config.SHADOW_COLOR, highlightthickness=2)
        status_panel.pack(side=tk.LEFT, padx=(0,10), pady=10, fill=tk.Y)
        status_panel.pack_propagate(False)
        tk.Label(status_panel, text="NODE STATUS", font=(self.config.FONT_FAMILY, 16, "bold"), bg=self.config.STATUS_PANEL_BG, fg=self.config.SECONDARY_ACCENT).pack(pady=15, padx=10, anchor='w')
        self.status_label = tk.Label(status_panel, text="", bg=self.config.STATUS_PANEL_BG, fg=self.config.FG_COLOR, justify=tk.LEFT, padx=15, wraplength=230, 
                                     font=(self.config.FONT_FAMILY, self.config.FONT_SIZE-1))
        self.status_label.pack(pady=10, fill=tk.X, anchor='n')
        
        chat_area_frame = tk.Frame(content_frame, bg=self.config.BG_COLOR)
        chat_area_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, pady=10)
        self.chat_text = tk.Text(chat_area_frame, bg=self.config.PANEL_BG, fg=self.config.FG_COLOR, wrap=tk.WORD, state=tk.DISABLED, 
                                 relief=tk.FLAT, highlightbackground=self.config.SHADOW_COLOR, highlightthickness=2, padx=10, pady=10, 
                                 font=(self.config.FONT_FAMILY, self.config.FONT_SIZE))
        self.chat_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar = ttk.Scrollbar(chat_area_frame, orient=tk.VERTICAL, command=self.chat_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.config(yscrollcommand=scrollbar.set)
        
        default_font = (self.config.FONT_FAMILY, self.config.FONT_SIZE)
        italic_font = (self.config.FONT_FAMILY, self.config.FONT_SIZE, "italic")
        bold_font = (self.config.FONT_FAMILY, self.config.FONT_SIZE, "bold")
        timestamp_font = (self.config.FONT_FAMILY, self.config.FONT_SIZE-1)
        self.chat_text.tag_configure("sent", foreground=self.config.ACCENT_COLOR, font=default_font, lmargin1=10, lmargin2=10, rmargin=10)
        self.chat_text.tag_configure("received", foreground="#E0E0E0", font=default_font, lmargin1=10, lmargin2=10, rmargin=10) 
        self.chat_text.tag_configure("system", foreground=self.config.SECONDARY_ACCENT, font=italic_font, lmargin1=10, lmargin2=10, rmargin=10)
        self.chat_text.tag_configure("error", foreground="#FF5555", font=bold_font, lmargin1=10, lmargin2=10, rmargin=10)
        self.chat_text.tag_configure("timestamp", foreground="#6272A4", font=timestamp_font) 

        input_controls_frame = tk.Frame(self.root, bg=self.config.BG_COLOR)
        input_controls_frame.pack(fill=tk.X, padx=15, pady=(0,10))
        self.input_entry = tk.Entry(input_controls_frame, bg=self.config.PANEL_BG, fg=self.config.FG_COLOR, relief=tk.FLAT, 
                                    highlightthickness=1, highlightbackground=self.config.ACCENT_COLOR, 
                                    insertbackground=self.config.SECONDARY_ACCENT, font=(self.config.FONT_FAMILY, self.config.FONT_SIZE+1))
        self.input_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=6, padx=(0,10))
        self.input_entry.bind("<Return>", lambda event: self.send_gui_message_action())
        send_button = tk.Button(input_controls_frame, text="Send", command=self.send_gui_message_action, 
                                bg=self.config.ACCENT_COLOR, fg=self.config.BG_COLOR, relief=tk.FLAT, 
                                font=(self.config.FONT_FAMILY, self.config.FONT_SIZE), width=8)
        send_button.pack(side=tk.LEFT)
        send_button.bind("<Enter>", lambda e: send_button.config(bg=self.config.BUTTON_HOVER_BG))
        send_button.bind("<Leave>", lambda e: send_button.config(bg=self.config.ACCENT_COLOR))
        
        utility_buttons_frame = tk.Frame(self.root, bg=self.config.BG_COLOR)
        utility_buttons_frame.pack(fill=tk.X, padx=15, pady=(0,15))
        button_font = (self.config.FONT_FAMILY, self.config.FONT_SIZE)
        button_bg = self.config.PANEL_BG
        
        def style_utility_button(btn):
            btn.config(bg=button_bg, fg=self.config.FG_COLOR, relief=tk.FLAT, font=button_font, highlightthickness=0)
            btn.bind("<Enter>", lambda e: btn.config(bg=self.config.BUTTON_HOVER_BG))
            btn.bind("<Leave>", lambda e: btn.config(bg=button_bg))

        clear_btn = tk.Button(utility_buttons_frame, text="Clear Chat", command=self.clear_chat_gui_action)
        style_utility_button(clear_btn)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.stealth_button = tk.Button(utility_buttons_frame, text="Stealth: OFF", command=self.toggle_ghost_mode_action)
        style_utility_button(self.stealth_button)
        self.stealth_button.pack(side=tk.LEFT, padx=5)
        
        self.compress_button = tk.Button(utility_buttons_frame, text="Compress: OFF", command=self.toggle_compression_action)
        style_utility_button(self.compress_button)
        self.compress_button.pack(side=tk.LEFT, padx=5)
        
        if self.network_manager.sock:
            ping_btn = tk.Button(utility_buttons_frame, text="Ping Node", command=lambda: self.handle_chat_command_action("/ping"))
            style_utility_button(ping_btn)
            ping_btn.pack(side=tk.LEFT, padx=5)
            
            who_btn = tk.Button(utility_buttons_frame, text="Who is Online?", command=lambda: self.handle_chat_command_action("/who"))
            style_utility_button(who_btn)
            who_btn.pack(side=tk.LEFT, padx=5)
        elif self.network_manager.server_socket:
            list_btn = tk.Button(utility_buttons_frame, text="List Clients", command=lambda: self.handle_chat_command_action("/who"))
            style_utility_button(list_btn)
            list_btn.pack(side=tk.LEFT, padx=5)

        disconnect_btn = tk.Button(utility_buttons_frame, text="Disconnect", command=self.disconnect_and_reset_action, 
                                   bg="#FF5555", fg=self.config.BG_COLOR, relief=tk.FLAT, font=button_font)
        disconnect_btn.pack(side=tk.RIGHT, padx=5)
        disconnect_btn.bind("<Enter>", lambda e: disconnect_btn.config(bg="#CC4444"))
        disconnect_btn.bind("<Leave>", lambda e: disconnect_btn.config(bg="#FF5555"))
        
        self.refresh_status_display()

    def get_status_text_content(self):
        # What's the vibe? This shows the status of our node.
        role = "Host" if self.network_manager.server_socket else "Client"
        token_to_display = self.token or (self.network_manager.crypto_engine.token if self.network_manager.crypto_engine else "N/A")
        token_snippet = f"{token_to_display[:4]}...{token_to_display[-4:]}" if token_to_display and len(token_to_display) > 8 else token_to_display
        
        status_lines = [
            f"Codename: {self.codename or 'N/A'}",
            f"Role: {role}",
        ]
        if role == "Host":
            try:
                port_num = self.network_manager.server_socket.getsockname()[1] if self.network_manager.server_socket and self.network_manager.server_socket.fileno() != -1 else 'N/A'
                status_lines.append(f"Listening Port: {port_num}")
            except Exception: 
                 status_lines.append("Listening Port: Error")
            status_lines.append(f"Auth Token: {token_snippet}")
            status_lines.append(f"Connected Clients: {len(self.network_manager.client_sockets)}")
        elif role == "Client":
            if self.network_manager.sock and self.network_manager.running:
                 status_lines.append(f"Connected to: {self.network_manager.ip}:{self.network_manager.port}")
                 status_lines.append(f"Auth Token Used: {token_snippet}")
            else:
                status_lines.append("Status: Disconnected")
        
        status_lines.append(f"Stealth Mode: {'ON' if self.ghost_mode else 'OFF'}")
        status_lines.append(f"Compression: {'ON' if self.network_manager.crypto_engine and self.network_manager.crypto_engine.compress_mode else 'OFF'}")
        return "\n".join(status_lines)

    def log_message_to_gui(self, text_message, is_sent=False, is_system=False, is_error=False):
        # Writing messages to the chat window, with style!
        log_level = logging.ERROR if is_error else logging.INFO
        
        if not self.chat_text or not self.chat_text.winfo_exists():
            fallback_log_msg = f"LOG_GUI_UNAVAILABLE: {text_message}"
            print(fallback_log_msg)
            logging.log(log_level, fallback_log_msg)
            return

        self.chat_text.config(state=tk.NORMAL)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_text.insert(tk.END, f"[{timestamp}] ", "timestamp")

        tag_to_use = "received"
        if is_error: tag_to_use = "error"
        elif is_system: tag_to_use = "system"
        elif is_sent: tag_to_use = "sent"
        
        self.chat_text.insert(tk.END, text_message + "\n\n", tag_to_use)
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)
        
        logging.log(log_level, f"GUI_LOG: {text_message}")

    def send_gui_message_action(self):
        # Sending a message from the chat box. Let's make some noise!
        message_content = self.input_entry.get().strip()
        if not message_content: return
        self.input_entry.delete(0, tk.END)
        
        if message_content.startswith("/"):
            self.handle_chat_command_action(message_content)
            return
            
        message_to_log_locally = self.network_manager.send_message(message_content, self.codename, self.ghost_mode)
        
        if message_to_log_locally:
            self.root.after(0, self.log_message_to_gui, message_to_log_locally, True, False, False) 
        elif not (self.network_manager.sock or (self.network_manager.server_socket and self.network_manager.client_sockets)):
            no_connection_msg = "[!] Cannot send: Not connected or no clients."
            if not self.network_manager.sock and not self.network_manager.server_socket:
                 no_connection_msg = "[!] Cannot send: Not connected to any node or hosting."
            elif self.network_manager.server_socket and not self.network_manager.client_sockets:
                 no_connection_msg = "[!] Cannot send: Hosting, but no clients connected."
            self.root.after(0, self.log_message_to_gui, no_connection_msg, False, True, True)

    def handle_chat_command_action(self, command_text):
        # Handling chat commands like a pro. /ping, /who, you name it!
        global start_time
        cmd_parts = command_text.lower().split()
        cmd_base = cmd_parts[0]

        if cmd_base == "/exit": self.disconnect_and_reset_action() 
        elif cmd_base == "/clear": self.clear_chat_gui_action()
        elif cmd_base == "/status": self.root.after(0, self.log_message_to_gui, self.get_status_text_content(), False, True, False)
        elif cmd_base == "/ghost": self.toggle_ghost_mode_action()
        elif cmd_base == "/compress": self.toggle_compression_action()
        elif cmd_base == "/who":
            if self.network_manager.server_socket:
                 with self.network_manager.lock:
                    if self.network_manager.client_sockets:
                        client_details = [f"'{name}' ({sock.getpeername()[0]})" for sock, name in self.network_manager.client_sockets]
                        self.root.after(0, self.log_message_to_gui, f"[*] Connected Clients ({len(client_details)}): {', '.join(client_details)}", False, True, False)
                    else:
                        self.root.after(0, self.log_message_to_gui, "[*] No clients currently connected.", False, True, False)
            elif self.network_manager.sock:
                try:
                    self.network_manager.sock.send(self.network_manager.crypto_engine.encrypt("/who"))
                    self.root.after(0, self.log_message_to_gui, "[*] Requested client list from node...", False, True, False)
                except Exception as e:
                    self.root.after(0, self.log_message_to_gui, f"[!] Failed to send /who command: {e}", False, True, True)
            else: self.root.after(0, self.log_message_to_gui, "[!] Command /who is unavailable when disconnected.", False, True, True)
        elif cmd_base == "/ping":
            if self.network_manager.sock:
                with start_time_lock: start_time = time.time()
                try:
                    self.network_manager.sock.send(self.network_manager.crypto_engine.encrypt("/ping"))
                    self.root.after(0, self.log_message_to_gui, "[*] Pinging node...", False, True, False)
                except Exception as e:
                    self.root.after(0, self.log_message_to_gui, f"[!] Ping failed: {e}", False, True, True)
            else: self.root.after(0, self.log_message_to_gui, "[!] Ping command is for clients connected to a node.", False, True, False)
        else: self.root.after(0, self.log_message_to_gui, f"[!] Unknown command: {command_text}", False, True, True)

    def toggle_ghost_mode_action(self):
        # Going incognito with ghost mode. Shh, nobody knows who you are!
        self.ghost_mode = not self.ghost_mode
        status_text = 'ON' if self.ghost_mode else 'OFF'
        if self.stealth_button and self.stealth_button.winfo_exists(): self.stealth_button.config(text=f"Stealth: {status_text}")
        self.root.after(0, self.log_message_to_gui, f"[*] Stealth mode is now {status_text.lower()}.", False, True, False)
        self.refresh_status_display()

    def toggle_compression_action(self):
        # Toggle compression to make messages lean and mean!
        if self.network_manager.crypto_engine:
            self.network_manager.crypto_engine.compress_mode = not self.network_manager.crypto_engine.compress_mode
            current_compress_mode = self.network_manager.crypto_engine.compress_mode
            status_text = 'ON' if current_compress_mode else 'OFF'
            if self.compress_button and self.compress_button.winfo_exists(): self.compress_button.config(text=f"Compress: {status_text}")
            self.root.after(0, self.log_message_to_gui, f"[*] Payload compression is now {status_text.lower()}.", False, True, False)
            self.refresh_status_display()
        else:
            self.root.after(0, self.log_message_to_gui, "[!] Cannot toggle compression: Crypto engine not initialized.", False, True, True)

    def clear_chat_gui_action(self):
        # Wiping the chat clean, like a digital eraser!
        if self.chat_text and self.chat_text.winfo_exists():
            self.chat_text.config(state=tk.NORMAL)
            self.chat_text.delete(1.0, tk.END)
            self.chat_text.config(state=tk.DISABLED)
        self.root.after(0, self.log_message_to_gui, "Chat cleared.", False, True, False)

    def disconnect_and_reset_action(self):
        # Time to leave the party and go back to the start screen.
        self.root.after(0, self.log_message_to_gui, "Disconnecting...", False, True, False)
        if self.network_manager:
            def _shutdown_and_reset():
                self.network_manager.shutdown() 
                self.root.after(0, self._reset_gui_to_mode_selection)
            threading.Thread(target=_shutdown_and_reset, daemon=True).start()
        else:
            self._reset_gui_to_mode_selection()

    def _reset_gui_to_mode_selection(self):
        # Resetting everything to square one. Fresh start, baby!
        self.passphrase = None
        self.token = None
        if self.network_manager.crypto_engine: self.network_manager.crypto_engine = None
        self.codename = None
        self.ghost_mode = False
        if self.stealth_button and self.stealth_button.winfo_exists(): self.stealth_button.config(text="Stealth: OFF")
        if self.compress_button and self.compress_button.winfo_exists(): self.compress_button.config(text="Compress: OFF")
        
        self.show_mode_selection_dialog()

    def handle_window_close_event(self): 
        # Closing the window? Let's make sure we shut down nicely.
        if messagebox.askokcancel("Quit", "Do you want to quit DarkWire Node? This will terminate all connections.", parent=self.root):
            if self.network_manager:
                shutdown_thread = threading.Thread(target=self.network_manager.shutdown, daemon=True)
                shutdown_thread.start()
                shutdown_thread.join(timeout=2.0) 
            
            self.root.quit()
            self.root.destroy()

    def refresh_status_display(self): 
        # Keeping the status panel fresh with the latest info.
        if self.status_label and self.status_label.winfo_exists():
             self.status_label.config(text=self.get_status_text_content())
        if self.title_label and self.title_label.winfo_exists(): 
            self.title_label.config(text=f"Mode: {'Host' if self.network_manager.server_socket else 'Client'} | Codename: {self.codename or 'N/A'}")

class Application:
    def __init__(self):
        self.config = Config()
        self.root = tk.Tk()
        self._setup_styles()
        self.network_manager = NetworkManager(
            self.config,
            None,
            self.on_message_from_network, 
            self.on_status_change_from_network 
        )
        self.gui_manager = GUIManager(
            self.root, 
            self.config, 
            self.network_manager
        )

    def _setup_styles(self):
        # Dressing up the GUI with some fancy styles!
        style = ttk.Style(self.root)
        style.theme_use('clam')  # Use 'clam' for maximum control over styling
        
        style.configure("Vertical.TScrollbar", 
                        gripcount=0,
                        background=self.config.PANEL_BG, 
                        darkcolor=self.config.ACCENT_COLOR, 
                        lightcolor=self.config.FG_COLOR,
                        troughcolor=self.config.BG_COLOR, 
                        bordercolor=self.config.BG_COLOR, 
                        arrowcolor=self.config.SECONDARY_ACCENT,
                        relief=tk.FLAT,
                        width=12)
        style.map("Vertical.TScrollbar",
                  background=[('active', self.config.BUTTON_HOVER_BG), ('!active', self.config.PANEL_BG)],
                  arrowcolor=[('pressed', self.config.BG_COLOR), ('!active', self.config.SECONDARY_ACCENT)])

    def on_message_from_network(self, message_text):
        # Messages from the network get logged to the GUI, with flair!
        is_err = message_text.strip().startswith("[!]")
        is_sys = message_text.strip().startswith("[*]") or is_err
        if hasattr(self.gui_manager, 'log_message_to_gui') and callable(self.gui_manager.log_message_to_gui):
            self.root.after(0, self.gui_manager.log_message_to_gui, message_text, False, is_sys, is_err)
        else: 
            print(f"AppLog (Msg): {message_text}")
            logging.info(f"AppLog_Msg_Fallback: {message_text}")

    def on_status_change_from_network(self):
        # Status changed? Let's update the GUI to reflect the new vibe.
        if hasattr(self.gui_manager, 'refresh_status_display') and callable(self.gui_manager.refresh_status_display):
            if self.gui_manager.root.winfo_exists():
                self.root.after(0, self.gui_manager.refresh_status_display)
        else: 
            print("AppLog (Status): Status update invoked, but GUI handler not ready.")
            logging.info("AppLog_Status_Fallback: Status update, GUI handler not ready.")

    def run(self):
        # Starting the show! Let's get this GUI party rolling.
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            if hasattr(self, 'gui_manager') and self.gui_manager.root.winfo_exists():
                 self.gui_manager.handle_window_close_event()
        finally:
            if self.network_manager and self.network_manager.running:
                logging.info("Application run loop ended, ensuring network shutdown.")
                self.network_manager.shutdown()

if __name__ == "__main__":
    start_time = None 
    start_time_lock = threading.Lock() 
    app = Application()
    app.run()