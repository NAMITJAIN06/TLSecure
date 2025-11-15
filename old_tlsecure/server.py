import socket
import threading
from aes_gcm import encrypt_message, decrypt_message
from ecdhe import generate_key_pair, derive_shared_key

HOST = '127.0.0.1'
PORT = 65432

server_private_key, server_public_key = generate_key_pair()
clients = {}  # Maps client sockets to their shared keys

def handle_client(client_socket, addr):
    print(f"[+] New connection from  client hello{addr} ")

    # Step 1: ECDHE handshake
    client_public_key_bytes = client_socket.recv(512)
    client_socket.sendall(server_public_key)
    shared_key = derive_shared_key(server_private_key, client_public_key_bytes)
    clients[client_socket] = shared_key

    # Step 2: Receive and broadcast messages
    try:
        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                break
            message = decrypt_message(shared_key, encrypted_data)
            print(f"[{addr}] {message}")
            broadcast_message(client_socket, message)
    except:
        pass
    finally:
        print(f"[-] Connection closed {addr}")
        clients.pop(client_socket)
        client_socket.close()

def broadcast_message(sender_socket, message):
    for client_socket, key in clients.items():
        if client_socket != sender_socket:
            encrypted_message = encrypt_message(key, message)
            client_socket.sendall(encrypted_message)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
