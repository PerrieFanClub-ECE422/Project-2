import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dbsetup import db_check_user_exists
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import sqlite3

def run_linux_command(command):
    # Execute the command
    exit_status = os.system(command)

def generate_key_pair(key_size=2048):
    """
    Generate an RSA key pair.

    Args:
        key_size (int): The size of the key in bits (default is 2048).

    Returns:
        tuple: A tuple containing the public key and private key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

def encrypt_with_public_key(public_key, plaintext):
    """
    Encrypt data using a public key.

    Args:
        public_key (RSAPublicKey): The public key used for encryption.
        plaintext (bytes): The data to be encrypted.

    Returns:
        bytes: The encrypted data.
    """
    encrypted_data = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_with_private_key(private_key, encrypted_data):
    """
    Decrypt data using a private key.

    Args:
        private_key (RSAPrivateKey): The private key used for decryption.
        encrypted_data (bytes): The encrypted data to be decrypted.

    Returns:
        bytes: The decrypted data.
    """
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

def validate_user(username, key):
    if not db_check_user_exists(username):
        return -1
    
    return 

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def serialize_key(key):
    """Serialize a public or private key."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(serialized_key):
    """Deserialize a serialized public key."""
    return serialization.load_pem_public_key(serialized_key)

def serialize_private_key(key):
    """Serialize a private key."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(serialized_key):
    """Deserialize a serialized private key."""
    return serialization.load_pem_private_key(
        serialized_key,
        password=None,
    )

def retrieve_private_key(username):
    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return deserialize_private_key(row[0])
    else:
        return None

def retrieve_public_key(username):
    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return serialization.load_pem_public_key(row[0])
    else:
        return None
    
# Example usage:
# key = generate_key()
# message = "Hello, this is a secret message."
# encrypted_message = encrypt_message(message, key)
# print("Encrypted message:", encrypted_message)

# decrypted_message = decrypt_message(encrypted_message, key)
# print("Decrypted message:", decrypted_message)
