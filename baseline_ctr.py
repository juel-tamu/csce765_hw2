import os
import time
import socket
import threading
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.0.1'
LOCAL_PORT = 8888
REMOTE_PORT = 8889

# Generate a random 32 byte (256-bit) secret key and a 16-byte IV
key = os.urandom(32)
iv = os.urandom(16)

# Initialize the AES cipher in CTR mode
CIPHER = Cipher(algorithms.AES(key), modes.CTR(iv))

def relay(ciphertext):
    ciphertext_bytearray = bytearray(ciphertext)

    # Original approach below, results in string "PAIT"
    # ciphertext_bytearray[12] ^= (1 << 1)
    # ciphertext_bytearray[13] ^= (1 << 2)
    # ciphertext_bytearray[14] ^= (1 << 3)
    # ciphertext_bytearray[15] ^= (1 << 4)

    needed_mask = [a ^ b for a, b in zip(b"READ", b"OPEN")]
    for i in range(12, 16):
        ciphertext_bytearray[i] ^= needed_mask[i - 12]
    
    return bytes(ciphertext_bytearray)


def handle_mitm():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    downstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((HOST, LOCAL_PORT))
        server.listen(5)

        client_socket, _ = server.accept()
        downstream.connect((HOST, REMOTE_PORT))

        ciphertext = client_socket.recv(4096)
        modified = relay(ciphertext)

        print("Intercepted client data")
        print("Original: ", ciphertext.hex())
        print("Modified: ", modified.hex())

        # Forward toward downstream
        downstream.sendall(modified)
        time.sleep(5)
        downstream.sendall(modified)

    finally:
        server.close()
        downstream.close()

def deliver_message(source: socket):
    try:
        while True:
            ciphertext = source.recv(4096)
            if not ciphertext:
                break
            
            # Decrypt data
            print(f"[*] Received ciphertext from client at {datetime.now().time()}")
            decryptor = CIPHER.decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

            print("Decrypted:", decrypted_message.decode())
    finally:
        source.close()

def dispatch_message(cipher: Cipher):
    # Encrypt data
    plaintext_command = '{"action": "READ", "path": "notes.txt"}'
    message = plaintext_command.encode()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    print("Ciphertext upon dispatch:", ciphertext.hex())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, LOCAL_PORT))
        client_socket.sendall(ciphertext)
        client_socket.close()

def main():
    # Create a local socket to simulate a MITM attack
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, REMOTE_PORT))
    server.listen(5)
    print(f"[*] MitM proxy listening on {HOST}:{REMOTE_PORT}")

    threading.Thread(target=handle_mitm,).start()
    dispatch_message(CIPHER)

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr}")
            threading.Thread(target=deliver_message, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("[*] Shutting down proxy.")
    finally:
        server.close()

if __name__ == "__main__":
    main()