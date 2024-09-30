# chat_app.py

import os
import re
import json
import socket
import random
import threading
import hashlib
import tkinter as tk
from dataclasses import dataclass
from typing import Optional


# ---------------------------- Data Classes ---------------------------- #

@dataclass
class PublicKey:
    N: int
    E: int


@dataclass
class PrivateKey:
    D: int


@dataclass
class RSAKeyPair:
    public_key: PublicKey
    private_key: PrivateKey


# ---------------------------- RSA Class ---------------------------- #

class RSA:
    """Class to handle RSA key generation, encryption, decryption, signing, and verification."""

    def __init__(self, key_length=2048):
        self.key_length = key_length
        self.key_pair: Optional[RSAKeyPair] = None

    def generate_keys(self):
        """Generates RSA key pair and stores it in the instance."""
        L = self.key_length
        while True:
            p = self.generate_prime_number(L // 2)
            q = self.generate_prime_number(L // 2)
            if p != q:
                n = p * q
                totient = self.lcm(p - 1, q - 1)
                while True:
                    e = random.randrange(2**16, 2**17)
                    if self.gcd(e, totient) == 1:
                        break
                d = self.modinv(e, totient)
                self.key_pair = RSAKeyPair(
                    public_key=PublicKey(N=n, E=e),
                    private_key=PrivateKey(D=d)
                )
                return

    @staticmethod
    def gcd(a, b):
        """Calculates the Greatest Common Divisor (GCD) of two numbers."""
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def lcm(a, b):
        """Calculates the Least Common Multiple (LCM) of two numbers."""
        return abs(a * b) // RSA.gcd(a, b)

    @staticmethod
    def xgcd(a, b):
        """Extended Euclidean Algorithm."""
        prevx, x = 1, 0
        prevy, y = 0, 1
        while b != 0:
            q = a // b
            x, prevx = prevx - q * x, x
            y, prevy = prevy - q * y, y
            a, b = b, a % b
        return a, prevx, prevy

    @staticmethod
    def modinv(a, m):
        """Calculates the modular inverse of a modulo m."""
        g, x, _ = RSA.xgcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    @staticmethod
    def is_prime(n, k=128):
        """Miller-Rabin primality test."""
        if n in (2, 3):
            return True
        if n <= 1 or n % 2 == 0:
            return False
        s, r = 0, n - 1
        while r % 2 == 0:
            s += 1
            r //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, r, n)
            if x not in (1, n - 1):
                for __ in range(s - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
        return True

    def generate_prime_number(self, length):
        """Generates a prime number of specified bit length."""
        while True:
            p = random.getrandbits(length)
            p |= (1 << length - 1) | 1  # Ensure p is odd and has the correct bit length
            if self.is_prime(p):
                return p

    def encrypt(self, message, public_key):
        """Encrypts a message using the recipient's public key."""
        return [pow(ord(char), public_key.E, public_key.N) for char in message]

    def decrypt(self, encrypted_message):
        """Decrypts an encrypted message using the private key."""
        if not self.key_pair:
            raise Exception('Key pair not generated')
        return ''.join([chr(pow(char_code, self.key_pair.private_key.D, self.key_pair.public_key.N))
                        for char_code in encrypted_message])

    @staticmethod
    def create_hash(message):
        """Creates a SHA-256 hash of the message."""
        return hashlib.sha256(message.encode()).hexdigest()

    def sign(self, message):
        """Signs a message using the private key."""
        if not self.key_pair:
            raise Exception('Key pair not generated')
        hash_message = self.create_hash(message)
        return pow(int(hash_message, 16), self.key_pair.private_key.D, self.key_pair.public_key.N)

    def verify(self, message, signature, public_key):
        """Verifies a message signature using the sender's public key."""
        hash_message = self.create_hash(message)
        hash_from_signature = pow(signature, public_key.E, public_key.N)
        return int(hash_message, 16) == hash_from_signature


# ---------------------------- Chat Application Class ---------------------------- #

class ChatApp:
    """Main class for the RSA Chat Application."""

    def __init__(self):
        # RSA instance
        self.rsa = RSA()

        # Networking
        self.client_socket = None
        self.header_size = 10
        self.port = 5000  # Default port

        # Public keys of other clients
        self.other_public_keys = {}  # Mapping from nickname to PublicKey

        # GUI
        self.window = tk.Tk()
        self.window.title("RSA Chat")
        self.window.geometry("800x600")
        self.setup_gui()

        # Paths
        self.stored_keys_file = os.path.join(os.getenv('LOCALAPPDATA') or '.', 'storedKeys.json')

    # ---------------------------- GUI Setup ---------------------------- #

    def setup_gui(self):
        """Sets up the GUI components."""
        button_width = 15
        entry_width = 20
        ip_entry_width = 30

        # Key Frame
        key_frame = tk.Frame(self.window)
        key_frame.grid(row=0, column=0, sticky='ew', padx=5, pady=5)

        tk.Button(key_frame, text="Load Stored Keys", command=self.load_stored_keys, width=button_width).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(key_frame, text="Generate New Keys", command=self.generate_new_keys, width=button_width).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(key_frame, text="(Press one of the buttons to initialize keys)").grid(row=0, column=2, padx=5, pady=5)

        # Key Display Frame
        key_display_frame = tk.Frame(self.window)
        key_display_frame.grid(row=1, column=0, sticky='ew', padx=5, pady=5)

        tk.Label(key_display_frame, text="E: ").grid(row=0, column=0, padx=5, pady=5)
        self.e_entry = tk.Entry(key_display_frame, width=entry_width, state='readonly')
        self.e_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(key_display_frame, text="N: ").grid(row=0, column=2, padx=5, pady=5)
        self.n_entry = tk.Entry(key_display_frame, width=entry_width, state='readonly')
        self.n_entry.grid(row=0, column=3, padx=5, pady=5)
        tk.Label(key_display_frame, text="D: ").grid(row=0, column=4, padx=5, pady=5)
        self.d_entry = tk.Entry(key_display_frame, width=entry_width, state='readonly')
        self.d_entry.grid(row=0, column=5, padx=5, pady=5)

        # Connection Frame
        connection_frame = tk.Frame(self.window)
        connection_frame.grid(row=2, column=0, sticky='ew', padx=5, pady=5)

        tk.Label(connection_frame, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
        self.server_ip_entry = tk.Entry(connection_frame, width=ip_entry_width)
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(connection_frame, text="Port:").grid(row=0, column=2, padx=5, pady=5)
        self.port_entry = tk.Entry(connection_frame, width=entry_width)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        self.port_entry.insert(0, str(self.port))
        tk.Button(connection_frame, text="Connect", command=self.connect_to_server, width=button_width).grid(row=0, column=4, padx=5, pady=5)

        # Nickname Frame
        nickname_frame = tk.Frame(self.window)
        nickname_frame.grid(row=3, column=0, sticky='ew', padx=5, pady=5)
        tk.Label(nickname_frame, text="Nickname:").grid(row=0, column=0, padx=5, pady=5)
        self.nickname_entry = tk.Entry(nickname_frame, width=20)
        self.nickname_entry.grid(row=0, column=1, padx=5, pady=5)
        self.nickname_entry.insert(tk.END, "Anonymous")

        # Chat and Clients Frame
        chat_clients_frame = tk.Frame(self.window)
        chat_clients_frame.grid(row=4, column=0, sticky='nsew', padx=5, pady=5)
        self.window.grid_rowconfigure(4, weight=1)
        self.window.grid_columnconfigure(0, weight=1)

        # Chat Text
        self.chat_text = tk.Text(chat_clients_frame, height=20, width=60, state='disabled')
        self.chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Connected Clients List
        clients_frame = tk.Frame(chat_clients_frame)
        clients_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        tk.Label(clients_frame, text="Connected Clients:").pack(anchor='nw')
        self.clients_listbox = tk.Listbox(clients_frame, height=20)
        self.clients_listbox.pack(fill=tk.Y, expand=True)

        # Message Entry Frame
        message_frame = tk.Frame(self.window)
        message_frame.grid(row=5, column=0, sticky='ew', padx=5, pady=5)
        tk.Label(message_frame, text="Your Message:").grid(row=0, column=0, padx=5, pady=5)
        self.message_entry = tk.Entry(message_frame, width=55)
        self.message_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(message_frame, text="Send", command=self.send_message, width=button_width).grid(row=0, column=2, padx=5, pady=5)

        # Disconnect Button
        tk.Button(self.window, text="Disconnect", command=self.disconnect, width=button_width).grid(row=6, column=0, padx=5, pady=5)

        # Bind Enter key to send message
        self.window.bind('<Return>', lambda event: self.send_message())

    # ---------------------------- Key Management ---------------------------- #

    def generate_new_keys(self):
        """Generates new RSA keys and updates the display."""
        self.rsa.generate_keys()
        self.store_keys()
        self.update_key_display()
        self.update_chat("New keys generated.")

    def load_stored_keys(self):
        """Loads stored RSA keys from file and updates the display."""
        try:
            with open(self.stored_keys_file, 'r') as f:
                keys = json.load(f)
                public_key = PublicKey(N=keys['N'], E=keys['E'])
                private_key = PrivateKey(D=keys['D'])
                self.rsa.key_pair = RSAKeyPair(public_key=public_key, private_key=private_key)
                self.update_key_display()
                self.update_chat("Stored keys loaded.")
        except (FileNotFoundError, json.JSONDecodeError):
            self.update_chat("No stored keys found. Generating new keys...")
            self.generate_new_keys()

    def store_keys(self):
        """Stores the RSA keys to a file."""
        if self.rsa.key_pair:
            keys = {
                'N': self.rsa.key_pair.public_key.N,
                'E': self.rsa.key_pair.public_key.E,
                'D': self.rsa.key_pair.private_key.D
            }
            with open(self.stored_keys_file, 'w') as f:
                json.dump(keys, f)
            self.update_chat("Keys stored successfully.")

    def update_key_display(self):
        """Updates the GUI entries with the current keys."""
        if self.rsa.key_pair:
            self.e_entry.config(state='normal')
            self.n_entry.config(state='normal')
            self.d_entry.config(state='normal')

            self.e_entry.delete(0, tk.END)
            self.n_entry.delete(0, tk.END)
            self.d_entry.delete(0, tk.END)

            self.e_entry.insert(0, str(self.rsa.key_pair.public_key.E))
            self.n_entry.insert(0, str(self.rsa.key_pair.public_key.N))
            self.d_entry.insert(0, str(self.rsa.key_pair.private_key.D))

            self.e_entry.config(state='readonly')
            self.n_entry.config(state='readonly')
            self.d_entry.config(state='readonly')

    # ---------------------------- Networking ---------------------------- #

    def connect_to_server(self):
        """Connects to the server."""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = self.server_ip_entry.get()
        try:
            self.port = int(self.port_entry.get())
            self.client_socket.connect((host, self.port))
            self.update_chat(f"Connected to server {host}:{self.port}")
            self.start_listening_thread(self.client_socket)
            self.send_register_message()
        except Exception as e:
            self.update_chat(f"Connection error: {e}")

    def start_listening_thread(self, sock):
        """Starts a thread to listen for incoming messages."""
        threading.Thread(target=self.listen_for_messages, args=(sock,), daemon=True).start()

    def listen_for_messages(self, sock):
        """Listens for incoming messages from the socket."""
        while True:
            try:
                full_message = b""
                new_msg = True
                msg_length = 0
                while True:
                    message = sock.recv(16)
                    if new_msg:
                        msg_length = int(message[:self.header_size])
                        new_msg = False
                    full_message += message
                    if len(full_message) - self.header_size == msg_length:
                        break
                self.handle_received_message(full_message[self.header_size:].decode())
            except Exception as e:
                self.update_chat(f"Receiving error: {e}")
                break

    def send_data(self, data):
        """Sends data through the client socket."""
        if self.client_socket:
            message = data.encode()
            message_header = f"{len(message):<{self.header_size}}".encode()
            try:
                self.client_socket.sendall(message_header + message)
            except Exception as e:
                self.update_chat(f"Sending error: {e}")
        else:
            self.update_chat("Not connected to any server.")

    # ---------------------------- Message Handling ---------------------------- #

    def send_register_message(self):
        """Sends a register message to the server with nickname and public key."""
        if self.client_socket and self.rsa.key_pair:
            nickname = self.nickname_entry.get() or "Anonymous"
            public_key = {
                'N': self.rsa.key_pair.public_key.N,
                'E': self.rsa.key_pair.public_key.E
            }
            register_message = {
                'type': 'register',
                'nickname': nickname,
                'public_key': public_key
            }
            self.send_data(json.dumps(register_message))
            self.update_chat("Register message sent.")
        else:
            self.update_chat("Cannot register; no connection or keys not generated.")

    def send_message(self):
        """Encrypts and sends a message to the selected recipient."""
        message_text = self.message_entry.get()
        selection = self.clients_listbox.curselection()
        if selection:
            recipient = self.clients_listbox.get(selection[0])
            if recipient == self.nickname_entry.get():
                self.update_chat("Cannot send message to yourself.")
                return
            recipient_public_key = self.other_public_keys.get(recipient)
            if recipient_public_key and self.rsa.key_pair:
                signature = self.rsa.sign(message_text)
                encrypted_message = self.rsa.encrypt(message_text, recipient_public_key)
                nickname = self.nickname_entry.get() or "Anonymous"
                message_with_signature = {
                    'type': 'message',
                    'sender': nickname,
                    'recipient': recipient,
                    'message': encrypted_message,
                    'signature': signature
                }
                self.send_data(json.dumps(message_with_signature))
                self.update_chat(f"You to {recipient}: {message_text}")
                self.message_entry.delete(0, tk.END)
            else:
                self.update_chat(f"Cannot find public key for recipient {recipient}")
        else:
            self.update_chat("No recipient selected.")

    def handle_received_message(self, message):
        """Handles a received message."""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            if msg_type == 'client_list':
                clients = data.get('clients', [])
                self.update_clients_list(clients)
            elif msg_type == 'message':
                sender = data.get('sender', 'Unknown')
                encrypted_message = data.get('message')
                signature = data.get('signature')
                public_key = self.other_public_keys.get(sender)
                if not public_key:
                    self.update_chat(f"No public key for sender {sender}")
                    return
                decrypted_message = self.rsa.decrypt(encrypted_message)
                if self.rsa.verify(decrypted_message, signature, public_key):
                    self.update_chat(f"{sender}: {decrypted_message}")
                else:
                    self.update_chat(f"Signature verification failed for message from {sender}")
            else:
                self.update_chat(f"Unknown message type received: {msg_type}")
        except json.JSONDecodeError as e:
            self.update_chat(f"JSON decoding error: {e}")
        except Exception as e:
            self.update_chat(f"Message handling error: {e}")

    def update_clients_list(self, clients):
        """Updates the connected clients list."""
        self.clients_listbox.delete(0, tk.END)
        self.other_public_keys.clear()
        for client_info in clients:
            nickname = client_info['nickname']
            public_key_data = client_info['public_key']
            public_key = PublicKey(N=public_key_data['N'], E=public_key_data['E'])
            self.other_public_keys[nickname] = public_key
            self.clients_listbox.insert(tk.END, nickname)

    # ---------------------------- Utilities ---------------------------- #

    def update_chat(self, message):
        """Updates the chat display with a new message."""
        self.chat_text.config(state='normal')
        self.chat_text.insert(tk.END, f"{message}\n")
        self.chat_text.config(state='disabled')
        self.chat_text.see(tk.END)

    def disconnect(self):
        """Disconnects from the server and closes sockets."""
        if self.client_socket:
            try:
                disconnect_message = {'type': 'disconnect'}
                self.send_data(json.dumps(disconnect_message))
            except Exception as e:
                self.update_chat(f"Error sending disconnect message: {e}")
            self.client_socket.close()
            self.client_socket = None
            self.update_chat("Disconnected from server.")
        self.window.destroy()

    # ---------------------------- Run Application ---------------------------- #

    def run(self):
        """Runs the main application loop."""
        self.window.mainloop()


# ---------------------------- Main Execution ---------------------------- #

if __name__ == '__main__':
    app = ChatApp()
    app.run()
