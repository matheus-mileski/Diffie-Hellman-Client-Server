import socket
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key, load_pem_parameters
from modules.AESCipher import AESCipher
from modules.diffie_hellman import generate_private_key, generate_public_key, generate_shared_secret, receive_full_message, hash_content

# Server's host and port to connect to
SERVER_HOST = 'dh-server'
SERVER_PORT = 65432

def start_client(server_host, server_port, file_path=None):
    # Create a socket object
    connected = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        for i in range(1, 6):  # Try to connect 5 times
            try:
                s.connect((server_host, server_port))
                connected = True
                break
            
            except ConnectionRefusedError:
                print("Connection refused, retrying...")
                time.sleep(i*5)
        
        if not connected:
            print("Failed to connect to the server.")
            return

        print(f"Connected to server on ({server_host}, {server_port})")
        
        # Receive the DH parameters from the server
        pem_parameters = receive_full_message(s)
        dh_parameters = load_pem_parameters(
            pem_parameters, backend=default_backend()
        )
        
        # Generate client's Diffie-Hellman private and public key
        client_private_key = generate_private_key(dh_parameters)
        client_public_key = generate_public_key(client_private_key)

        # Send public key to the server
        client_public_key_bytes = client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        # print(f"Client Public Key (PEM):\n{client_public_key_bytes.decode('utf-8')}")
        s.sendall(client_public_key_bytes)

        # Receive the server's public key
        server_public_key_bytes = receive_full_message(s)
        # print(f"Client Received Server Public Key (UTF-8):\n{server_public_key_bytes.decode('utf-8')}")
        server_public_key = load_pem_public_key(server_public_key_bytes, backend=default_backend())
        
        # Derive the shared secret key
        shared_secret_key = generate_shared_secret(client_private_key, server_public_key)

        # Create an AES cipher with the derived shared secret key
        aes_cipher = AESCipher(shared_secret_key)

        # Encrypt and send data to the server
        message = b"Message from client"
        encrypted_message = aes_cipher.encrypt(message)
        message_hash = hash_content(message)
        s.sendall(b"\x00" + message_hash + encrypted_message)

        # Receive and decrypt the response from the server
        encrypted_response = receive_full_message(s)
        decrypted_response = aes_cipher.decrypt(encrypted_response)
        print(f"Received (decrypted): {decrypted_response}")
        
        if file_path is not None:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            print(file_content)
            file_content_encrypted = aes_cipher.encrypt(file_content)
            file_content_hash = hash_content(file_content)
            
            s.sendall(b"\x01" + file_content_hash + file_content_encrypted)

            encrypted_response = receive_full_message(s)
            decrypted_response = aes_cipher.decrypt(encrypted_response)
            print(f"Received (decrypted): {decrypted_response}")
            
        while True:
            pass


if __name__ == "__main__":    
    # Run the client    
    file_path = 'client/message.txt'
    start_client(SERVER_HOST, SERVER_PORT, file_path)
