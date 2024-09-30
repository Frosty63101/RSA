# server.py

import socket
import threading
import json

class ClientThread(threading.Thread):
    def __init__(self, client_socket, client_address, server):
        threading.Thread.__init__(self)
        self.sock = client_socket
        self.addr = client_address
        self.server = server
        self.nickname = None
        self.public_key = None
        self.header_size = 10

    def run(self):
        print(f"Client connected from {self.addr}")
        try:
            while True:
                full_message = b""
                new_msg = True
                msg_length = 0
                while True:
                    message = self.sock.recv(16)
                    if new_msg:
                        msg_length = int(message[:self.header_size])
                        new_msg = False
                    full_message += message
                    if len(full_message) - self.header_size == msg_length:
                        break
                data = full_message[self.header_size:].decode()
                self.handle_message(data)
        except Exception as e:
            print(f"Client {self.addr} disconnected: {e}")
            self.server.remove_client(self)
            self.sock.close()

    def handle_message(self, data):
        try:
            message = json.loads(data)
            msg_type = message.get('type')
            if msg_type == 'register':
                self.nickname = message['nickname']
                self.public_key = message['public_key']
                self.server.add_client(self)
                print(f"Client registered: {self.nickname}")
            elif msg_type == 'message':
                recipient_nickname = message['recipient']
                self.server.forward_message(message, recipient_nickname)
            elif msg_type == 'disconnect':
                print(f"Client {self.nickname} requested disconnect.")
                self.server.remove_client(self)
                self.sock.close()
            else:
                print(f"Unknown message type from {self.addr}: {msg_type}")
        except json.JSONDecodeError as e:
            print(f"JSON decode error from {self.addr}: {e}")

    def send_data(self, data):
        message = data.encode()
        message_header = f"{len(message):<{self.header_size}}".encode()
        try:
            self.sock.sendall(message_header + message)
        except Exception as e:
            print(f"Error sending data to {self.addr}: {e}")
            self.server.remove_client(self)
            self.sock.close()

class Server:
    def __init__(self, host='0.0.0.0', port=5000):
        self.clients = {}
        self.host = host
        self.port = port
        self.server_socket = None
        self.header_size = 10

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        print(f"Server started on {self.host}:{self.port}")
        try:
            while True:
                client_sock, client_addr = self.server_socket.accept()
                client_thread = ClientThread(client_sock, client_addr, self)
                client_thread.start()
        except KeyboardInterrupt:
            print("Server shutting down.")
        finally:
            self.server_socket.close()

    def add_client(self, client_thread):
        if client_thread.nickname:
            self.clients[client_thread.nickname] = client_thread
            print(f"Client {client_thread.nickname} added.")
            self.send_client_list()

    def remove_client(self, client_thread):
        if client_thread.nickname in self.clients:
            del self.clients[client_thread.nickname]
            print(f"Client {client_thread.nickname} removed.")
            self.send_client_list()

    def send_client_list(self):
        """Sends the list of connected clients to all clients."""
        client_list = []
        for nickname, client in self.clients.items():
            client_list.append({
                'nickname': nickname,
                'public_key': client.public_key
            })
        message = {
            'type': 'client_list',
            'clients': client_list
        }
        message_str = json.dumps(message)
        for client in self.clients.values():
            client.send_data(message_str)

    def forward_message(self, message, recipient_nickname):
        recipient = self.clients.get(recipient_nickname)
        if recipient:
            recipient.send_data(json.dumps(message))
            print(f"Forwarded message from {message['sender']} to {recipient_nickname}")
        else:
            print(f"Recipient {recipient_nickname} not found.")

if __name__ == '__main__':
    server = Server()
    server.start()
