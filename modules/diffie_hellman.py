from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidKey

# Function to generate Diffie-Hellman parameters
def generate_dh_parameters():
    # Use predefined 2048-bit prime
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

# Function to generate a private key from DH parameters
def generate_private_key(dh_parameters):
    private_key = dh_parameters.generate_private_key()
    return private_key

# Function to generate a public key from a private key
def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

# Function to generate a shared secret from a private key and peer's public key
def generate_shared_secret(private_key, peer_public_key):
    try:
        shared_secret = private_key.exchange(peer_public_key)
        # Perform key derivation
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key
    except InvalidKey:
        print("Invalid public key for exchange.")
        raise
    except Exception as e:
        print(f"Unexpected error during key exchange: {e}")
        raise

def receive_full_message(connection, buffer_size=2048):
    data = b""
    while True:
        part = connection.recv(buffer_size)
        data += part
        if len(part) < buffer_size:
            break
    return data

def hash_content(content):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(content)
    return digest.finalize()

if __name__ == "__main__":
    dh_parameters = generate_dh_parameters()
    print(dh_parameters)
    
    # Each party generates their own private key
    private_key_client = generate_private_key(dh_parameters)
    private_key_server = generate_private_key(dh_parameters)
    print(private_key_client)
    print(private_key_server)

    # Each party generates their public key to send to the other party
    public_key_client = generate_public_key(private_key_client)
    public_key_server = generate_public_key(private_key_server)
    print(public_key_client)
    print(public_key_server)

    # Exchange public keys and generate the shared secret
    shared_secret_client = generate_shared_secret(private_key_client, public_key_server)
    shared_secret_server = generate_shared_secret(private_key_server, public_key_client)
    print(shared_secret_client)
    print(shared_secret_server)

    # The shared secrets should be the same
    assert shared_secret_client == shared_secret_server, "Shared secrets do not match!"
