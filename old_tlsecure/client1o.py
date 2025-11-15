import socket
import threading
from aes_gcm import encrypt_message, decrypt_message
from ecdhe import generate_key_pair, derive_shared_key

HOST = '127.0.0.1'
PORT = 65432

def receive_messages(sock, shared_key):
    while True:
        try:
            encrypted_data = sock.recv(4096)
            if encrypted_data:
                message = decrypt_message(shared_key, encrypted_data)
                print(f"\n[New Message] {message}")
        except:
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Step 0: Send ClientHello and wait for ServerHello
    sock.sendall(b'ClientHello')
    server_response = sock.recv(1024)
    if server_response != b'ServerHello':
        print("[-] Handshake failed. Unexpected server response.")
        sock.close()
        return
    print("[*] ServerHello received. Proceeding with key exchange.")

    # Step 1: ECDHE handshake
    private_key, public_key = generate_key_pair()
    sock.sendall(public_key)
    server_public_key_bytes = sock.recv(512)
    shared_key = derive_shared_key(private_key, server_public_key_bytes)
    print("[*] Key exchange complete.")

    # Step 2: Start receiver thread
    thread = threading.Thread(target=receive_messages, args=(sock, shared_key))
    thread.start()

    # Step 3: Message sending loop
    while True:
        message = input("You: ")
        if message.lower() == "exit":
            break
        encrypted_message = encrypt_message(shared_key, message)
        sock.sendall(encrypted_message)

    sock.close()

if __name__ == "__main__":
    main()
