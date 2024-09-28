import socket
import tkinter as tk
import random
import threading
import json
import os
import re
from typing import Union
from dataclasses import dataclass
import hashlib

STOREDKEYSFILE = os.getenv('LOCALAPPDATA') + '\\storedKeys.json' # type: ignore
client_socket = None
other_public_key = None
mykey = None
CLIENT = 0
HEADER_SIZE = 10
PORT = 20

@dataclass
class RSAKey:
    public_key: Union['Public', None]
    private_key: Union['Private', None]
    pq: Union['PQ', None]

@dataclass
class Public:
    N: int
    E: int

@dataclass
class Private:
    lambdaN: int
    D: int

@dataclass
class PQ:
    P: int
    Q: int

def RSAKeyGen():
    L = 2048  # Key length in bits
    while True:
        p, q = generate_prime_number(L), generate_prime_number(L)
        if p != q:
            n = p * q
            totient = getLCM(p - 1, q - 1)
            while True:
                e = generate_prime_number(L // 32)
                if getGCD(e, totient) == 1:
                    break
            d = modInv(e, totient)
            return RSAKey(Public(N=n, E=e), Private(lambdaN=totient, D=d), PQ(P=p, Q=q))

def getGCD(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def getLCM(a, b):
    gcd = getGCD(a, b)
    return (a * b) // gcd

def xgcd(a,b):
    prevx, x = 1, 0; prevy, y = 0, 1
    while b != 0:
        q = int(int(a)//int(b))
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return a, prevx, prevy

def modInv(a, m):
    g, x, y = xgcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_prime(n, k=128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = random.getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return int(p)

def getKeys():
    print('Getting Keys')
    chat.configure(state='normal')
    chat.insert(tk.END, f"Getting keys\n")
    chat.configure(state='disabled')
    keys = RSAKeyGen()
    if keys and keys.public_key and keys.private_key and keys.pq:
        dictKeys = {'N': keys.public_key.N, 'E': keys.public_key.E, 'D': keys.private_key.D, \
                    'lambdaN': keys.private_key.lambdaN, 'P': keys.pq.P, 'Q': keys.pq.Q}
        storeKeys(dictKeys)

def storeKeys(keys):
    with open(STOREDKEYSFILE, 'w') as f:
        json.dump(keys, f)

def getStoredKeys():
    keys = []
    global mykey
    try:
        with open(STOREDKEYSFILE, 'r') as f:
            try:
                keys = json.load(f)
                if isinstance(keys, dict):
                    mykey = RSAKey(Public(keys['N'], keys['E']), Private(keys['lambdaN'], keys['D']), PQ(keys['P'], keys['Q']))
                else:
                    mykey = RSAKey(Public(keys.public_key.N, keys.public_key.E), Private(keys.private_key.lambdaN, keys.private_key.D), PQ(keys.pq.P, keys.pq.Q))
                return keys
            except json.decoder.JSONDecodeError:
                getKeys()
                getStoredKeys()
    except FileNotFoundError:
        with open(STOREDKEYSFILE, 'w') as file:
            pass
        getKeys()

def encrypt(message, key):
    ords = []
    if type(key) == Public:
        for char in message:
            n = pow(ord(char), key.E, key.N)
            ords.append(n)
    else:
        pass
    return ords

def decrypt(ords, key):
    message = ''
    if type(key) == RSAKey:
        for o in ords:
            if isinstance(o, int) and key.private_key and key.public_key:
                n = str(chr(pow(o, key.private_key.D, key.public_key.N)))
                message += n
            else:
                raise ValueError("Expected integer values for decryption")
    else:
        pass
    return message

def create_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

def sign(message, private_key, public_key):
    hash_message = create_hash(message)
    signature = pow(int(hash_message, 16), private_key.D, public_key.N)
    return signature

def verify(message, signature, public_key):
    hash_message = create_hash(message)
    hash_from_signature = pow(signature, public_key.E, public_key.N)
    return int(hash_message, 16) == hash_from_signature

def listen_for_messages(socket, on_message_received):
    while True:
        try:
            full_message = b""
            new_msg = True
            msg_length = 0
            while True:
                message = socket.recv(16)  
                if new_msg:
                    msg_length = int(message[:HEADER_SIZE])  
                    new_msg = False
                full_message += message
                if len(full_message) - HEADER_SIZE == msg_length:
                    on_message_received(full_message[HEADER_SIZE:].decode())
                    new_msg = True
                    full_message = b""
        except ConnectionResetError as e:
            print(f"Connection was reset: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Connection was reset: {e}\n")
            chat.configure(state='disabled')
            break
        except Exception as e:
            print(f"Error receiving message: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Error receiving message: {e}\n")
            chat.configure(state='disabled')
            break

def start_listening_thread(socket, on_message_received):
    listening_thread = threading.Thread(target=listen_for_messages, args=(socket, on_message_received))
    listening_thread.daemon = True
    listening_thread.start()

def is_valid_ip(ip):
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return re.fullmatch(pattern, ip) is not None

def is_valid_port(port):
    return 0 < port < 65536

def sendKeys():
    global client_socket
    try:
        N = NKey.get()
        E = EKey.get()
        if client_socket:
            key_message = f"KEYS:{N},{E}"
            send_message(client_socket, key_message)
        else:
            print("Client socket is not connected.")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Client socket is not connected\n")
            chat.configure(state='disabled')
    except Exception as e:
        print(f"Error sending keys: {e}")
        chat.configure(state='normal')
        chat.insert(tk.END, f"Error sending keys: {e}\n")
        chat.configure(state='disabled')

def Send():
    global other_public_key
    global client_socket
    global mykey 
    try:
        data = message_input.get()
        if other_public_key and mykey:
            signature = sign(data, mykey.private_key, mykey.public_key)
            encrypted_data = encrypt(data, other_public_key)
            message_with_signature = {"message": encrypted_data, "signature": signature}
            send_message(client_socket, json.dumps(message_with_signature))
            chat.configure(state='normal')
            chat.insert(tk.END, f"You: {data}\n")
            chat.configure(state='disabled')
            chat.see(tk.END)
            message_input.delete(0, tk.END)
        else:
            print("No public key available for encryption")
            chat.configure(state='normal')
            chat.insert(tk.END, f"No public key available for encryption\n")
            chat.configure(state='disabled')
    except Exception as e:
        print(f"Error sending data: {e}")
        chat.configure(state='normal')
        chat.insert(tk.END, f"Error sending data: {e}\n")
        chat.configure(state='disabled')

def send_message(socket, message):
    message = message.encode()
    message_header = f"{len(message):<{HEADER_SIZE}}".encode()
    socket.sendall(message_header + message)

def on_message_received(message):
    global mykey
    global other_public_key
    global CLIENT
    if message.startswith("KEYS:"):
        try:
            _, key_data = message.split(":", 1)
            keysList = key_data.split(",", 1)
            other_public_key = Public(int(keysList[0]), int(keysList[1]))
            if CLIENT == 0:
                sendKeys()
        except ValueError as e:
            print(f"Error processing keys: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Error processing keys: {e}\n")
            chat.configure(state='disabled')
    else:
        try:
            received_data = json.loads(message)
            encrypted_message = received_data["message"]
            signature = received_data["signature"]
            if mykey and all(isinstance(x, int) for x in encrypted_message):
                decrypted_message = decrypt(encrypted_message, mykey)
                if verify(decrypted_message, signature, other_public_key):
                    chat.configure(state='normal')
                    chat.insert(tk.END, f"{nick_input.get()}: {decrypted_message}\n")
                    chat.configure(state='disabled')
                else:
                    print("Signature verification failed")
                    chat.configure(state='normal')
                    chat.insert(tk.END, "SIGNATURE VERIFICATION FAILED\n")
                    chat.configure(state='disabled')
            else:
                print("Invalid message format or public key not available")
                chat.configure(state='normal')
                chat.insert(tk.END, f"Invalid message format or public key not available\n")
                chat.configure(state='disabled')
        except json.JSONDecodeError:
            print("Error decoding JSON message")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Error decoding JSON message\n")
            chat.configure(state='disabled')
        except Exception as e:
            print(f"Error in message decryption or signature verification: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Error in message decryption or signature verification: {e}\n")
            chat.configure(state='disabled')

def Client_Connect(s):
    global CLIENT
    global client_socket
    HOST = Client_Connect_IP.get()
    global PORT
    PORT = int(portBox.get().strip())
    keys = getStoredKeys()
    if keys:
        NKey.insert(tk.END, str(keys['N']))
        EKey.insert(tk.END, str(keys['E']))
    if is_valid_ip(HOST) and is_valid_port(PORT):
        try:
            s.connect((HOST, PORT))
            client_socket = s  
            start_listening_thread(s, on_message_received)
            print("Connected to server")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Connected to server\n")
            chat.configure(state='disabled')
            CLIENT = 1
            sendKeys()  
        except socket.error as e:
            print(f"Socket error: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Socket error: {e}\n")
            chat.configure(state='disabled')
        except Exception as e:
            print(f"General error: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"General error: {e}\n")
            chat.configure(state='disabled')
    else:
        print("Invalid IP or port")
        chat.configure(state='normal')
        chat.insert(tk.END, f"Invalid IP or port\n")
        chat.configure(state='disabled')

def Host_Connect(s):
    keys = getStoredKeys()
    if keys:
        NKey.insert(tk.END, str(keys['N']))
        EKey.insert(tk.END, str(keys['E']))
    machineName = socket.gethostname()
    IP = socket.gethostbyname(machineName)
    global PORT
    PORT = int(portBox.get().strip())
    Host_IP.configure(state='normal')
    Host_IP.delete(0, tk.END)  
    Host_IP.insert(tk.END, IP)
    Host_IP.configure(state='readonly')
    s.bind((IP, PORT))
    s.listen(1)
    print("Server listening on", IP, ":", PORT)
    chat.configure(state='normal')
    chat.insert(tk.END, f"Server listening on: {IP}:{PORT}\n")
    chat.configure(state='disabled')

    threading.Thread(target=accept_connections, args=(s,), daemon=True).start()

def accept_connections(s):
    global client_socket
    while True:
        try:
            conn, addr = s.accept()
            print(f"Connected to {addr}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Connected to: {addr}\n")
            chat.configure(state='disabled')
            client_socket = conn  
            start_listening_thread(conn, on_message_received)
        except Exception as e:
            print(f"Error accepting connections: {e}")
            chat.configure(state='normal')
            chat.insert(tk.END, f"Error accepting connections: {e}\n")
            chat.configure(state='disabled')
            break

def getStoredKeysText():
    global mykey
    keys = []
    try:
        with open(STOREDKEYSFILE, 'r') as f:
            try:
                keys = json.load(f)
                EKey.config(state='normal')
                EKey.delete(0, tk.END)  
                EKey.insert(0, str(keys['E']))  
                EKey.config(state='readonly')
                NKey.config(state='normal')
                NKey.delete(0, tk.END)  
                NKey.insert(0, str(keys['N']))  
                NKey.config(state='readonly')
                DKey.config(state='normal')
                DKey.delete(0, tk.END)  
                DKey.insert(0, str(keys['D']))  
                DKey.config(state='readonly')
                mykey = RSAKey(Public(keys['N'], keys['E']), Private(keys['lambdaN'], keys['D']), PQ(keys['P'], keys['Q']))
            except json.decoder.JSONDecodeError:
                getKeys()
                getStoredKeys()
    except FileNotFoundError:
        with open(STOREDKEYSFILE, 'w') as file:
            pass
        getKeys()

def getKeysText():
    global mykey
    keys = RSAKeyGen()
    if keys and keys.public_key and keys.private_key and keys.pq:
        dictKeys = {'N': keys.public_key.N, 'E': keys.public_key.E, 'D': keys.private_key.D, \
                'lambdaN': keys.private_key.lambdaN, 'P': keys.pq.P, 'Q': keys.pq.Q}
        mykey = RSAKey(Public(dictKeys['N'], dictKeys['E']), Private(dictKeys['lambdaN'], dictKeys['D']), PQ(dictKeys['P'], dictKeys['Q']))
        storeKeys(dictKeys)
        EKey.config(state='normal')
        EKey.delete(0, tk.END) 
        EKey.insert(0, str(keys.public_key.E)) 
        EKey.config(state='readonly')
        NKey.config(state='normal')
        NKey.delete(0, tk.END) 
        NKey.insert(0, str(keys.public_key.N)) 
        NKey.config(state='readonly')
        DKey.config(state='normal')
        DKey.delete(0, tk.END)
        DKey.insert(0, str(keys.private_key.D))
        DKey.config(state='readonly')

def on_key_press(event):
    Send()

def Disconnect(s):
    s.close()
    print("Disconnected from server")
    chat.configure(state='normal')
    chat.insert(tk.END, f"Disconnected from server\n")
    chat.configure(state='disabled')
    #close the window and exit the program
    window.destroy()

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    window = tk.Tk()
    window.geometry("1000x500")
    window.title("RSA Chat")

    button_width = 15
    entry_width = 20
    ip_entry_width = 30

    # Row 0: Keys
    getStoredKeysButton = tk.Button(window, text="Get Stored Keys", command=getStoredKeysText, width=button_width)
    getStoredKeysButton.grid(row=0, column=0, padx=5, pady=5)
    getKeysButton = tk.Button(window, text="Get New Keys", command=getKeysText, width=button_width)
    getKeysButton.grid(row=0, column=1, padx=5, pady=5)
    instructions_label = tk.Label(window, text="you must press one of the buttons to \nget the keys before doing anything")
    instructions_label.grid(row=0, column=2, padx=5, pady=5)
    sendKeysButton = tk.Button(window, text="Send Keys", command=sendKeys, width=button_width)
    sendKeysButton.grid(row=0, column=3, padx=5, pady=5)
    portBox = tk.Entry(window, width=entry_width)
    portBox.grid(row=0, column=4, padx=5, pady=5)
    portBox.insert(0, str(PORT))

    # Row 1: E, N, and D Key Display
    tk.Label(window, text="E: ").grid(row=1, column=0, padx=5, pady=5)
    EKey = tk.Entry(window, width=entry_width, state='readonly')
    EKey.grid(row=1, column=1, padx=5, pady=5)
    tk.Label(window, text="N: ").grid(row=1, column=2, padx=5, pady=5)
    NKey = tk.Entry(window, width=entry_width, state='readonly')
    NKey.grid(row=1, column=3, padx=5, pady=5)
    tk.Label(window, text="D: ").grid(row=1, column=4, padx=5, pady=5)
    DKey = tk.Entry(window, width=entry_width, state='readonly')
    DKey.grid(row=1, column=5, padx=5, pady=5)

    # Row 2: Host and Client Connection
    Host_Button = tk.Button(window, text="Host", command=lambda: Host_Connect(s), width=button_width)
    Host_Button.grid(row=2, column=0, padx=5, pady=5)
    Host_IP_Entry_Label = tk.Label(window, text="Your IP:")
    Host_IP_Entry_Label.grid(row=2, column=1, padx=5, pady=5)
    Host_IP = tk.Entry(window, width=ip_entry_width, state='readonly')
    Host_IP.grid(row=2, column=2, padx=5, pady=5)
    Client_Connect_IP_Label = tk.Label(window, text="Server IP:")
    Client_Connect_IP_Label.grid(row=2, column=3, padx=5, pady=5)
    Client_Connect_IP = tk.Entry(window, width=ip_entry_width)
    Client_Connect_IP.grid(row=2, column=4, padx=5, pady=5)
    Client_Button = tk.Button(window, text="Connect", command=lambda: Client_Connect(s), width=button_width)
    Client_Button.grid(row=2, column=5, padx=5, pady=5)

    # Row 3: Chat Textbox and Send Button
    chat = tk.Text(window, height=10, width=65)
    chat.grid(row=3, column=0, columnspan=5, padx=5, pady=5)
    chat.configure(state='disabled')
    nick_label = tk.Label(window, text="Nickname:")
    nick_label.grid(row=3, column=4, padx=5, pady=5)
    nick_input = tk.Entry(window, width=20)
    nick_input.grid(row=3, column=5, columnspan=3, padx=5, pady=5)
    nick_input.insert(tk.END, "Anonymous")

    message_label = tk.Label(window, text="Your Message:")
    message_label.grid(row=4, column=0, padx=5, pady=5)
    message_input = tk.Entry(window, width=55)
    message_input.grid(row=4, column=1, columnspan=3, padx=5, pady=5)
    send = tk.Button(window, text="Send", command=Send, width=button_width)
    send.grid(row=4, column=4, padx=5, pady=5)

    # Row 5: Disconnect Button
    Disconnect_Button = tk.Button(window, text="Disconnect", command=lambda: Disconnect(s), width=button_width)
    Disconnect_Button.grid(row=5, column=0, padx=5, pady=5)

    window.bind('<Return>', on_key_press)

    window.mainloop()