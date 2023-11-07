import socket
import threading
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key, ParameterFormat
from cryptography.hazmat.backends import default_backend
from modules.AESCipher import AESCipher
from modules.diffie_hellman import generate_private_key, generate_public_key, generate_shared_secret, generate_dh_parameters, receive_full_message, hash_content


# Define the host and the port for the server
HOST = '0.0.0.0'
PORT = 65432

def handle_client(connection, address, dh_parameters):
    print(f"Connected to {address}")

    # Serialize and send the DH parameters to the client
    pem_parameters = dh_parameters.parameter_bytes(
        encoding=Encoding.PEM,
        format=ParameterFormat.PKCS3
    )
    connection.sendall(pem_parameters)
    
    # Generate the server's private and public key
    server_private_key = generate_private_key(dh_parameters)
    server_public_key = generate_public_key(server_private_key)

    # Send the server's public key to the client
    server_public_key_bytes = server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    # print(f"Server Public Key (PEM):\n{server_public_key_bytes.decode('utf-8')}")
    connection.sendall(server_public_key_bytes)

    # Receive the client's public key
    client_public_key_bytes = receive_full_message(connection)
    # print(f"Server Received Client Public Key (UTF-8):\n{client_public_key_bytes.decode('utf-8')}")
    client_public_key = load_pem_public_key(client_public_key_bytes, backend=default_backend())
    
    # Generate the shared secret key
    shared_secret_key = generate_shared_secret(server_private_key, client_public_key)

    # Create an AES cipher with the derived shared secret key
    aes_cipher = AESCipher(shared_secret_key)

    # Wait to receive data from the client
    while True:
        data = receive_full_message(connection, 1024)
        
        if not data:
            break
        
        flag = data[0:1]
        received_hash = data[1:33]  # Assuming SHA-256 hash size
        encrypted_content = data[33:]
                    
        # Decrypt the received data using the AES cipher
        decrypted_content = aes_cipher.decrypt(encrypted_content)
        
        calculated_hash = hash_content(decrypted_content)
        
        if received_hash != calculated_hash:
            encrypted_response = aes_cipher.encrypt(b"Content integrity check failed.")
            connection.sendall(encrypted_response)
        elif flag == b"\x01":
            encrypted_response = aes_cipher.encrypt(b"File received successfully.")
            connection.sendall(encrypted_response)
            print(f"Received (decrypted): {decrypted_content}")
            with open('server/received_file.txt', 'wb') as f:
                f.write(decrypted_content)
        else:
            print(f"Received (decrypted): {decrypted_content}")
            encrypted_response = aes_cipher.encrypt(b"Response from server")
            connection.sendall(encrypted_response)

        
    connection.close()
    print(f"Connection to {address} closed")

def start_server(host, port):
    # Generate Diffie-Hellman parameters (usually done once and reused)
    dh_parameters = generate_dh_parameters()

    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        # Handle clients indefinitely
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, dh_parameters))
            client_thread.start()

# Run the server
if __name__ == "__main__":
    start_server(HOST, PORT)
