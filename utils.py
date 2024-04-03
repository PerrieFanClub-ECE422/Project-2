import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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

# def validate_user(username_asking, username_key):
#     if not db_check_user_exists(username_asking):
#         return -1
#     #check permissions for username_asking TODO
    
#     return get_public_key(username_key), get_private_key(username_key)


def serialize_key(key):
    """Serialize a public or private key."""
    if isinstance(key, rsa.RSAPublicKey):
        return serialize_public_key(key)
    elif isinstance(key, rsa.RSAPrivateKey):
        return serialize_private_key(key)
    else:
        raise ValueError("Unsupported key type")

def serialize_public_key(key):
    """Serialize a public key."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(key):
    """Serialize a private key."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def deserialize_key(serialized_key):
    """Deserialize a serialized key."""
    # Determine the key type based on the serialized key data
    key_type = serialization.load_pem_private_key if b"PRIVATE" in serialized_key else serialization.load_pem_public_key

    # Deserialize the key using the appropriate function
    return key_type(
        serialized_key,
        password=None  # Assuming no password protection for keys
    )
