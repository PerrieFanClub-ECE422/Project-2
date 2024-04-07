import os
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_key_pair(key_size=2048):
    """
    Generate an RSA key pair.

    Args:
        key_size (int): The size of the key in bits (default is 2048).

    Returns:
        tuple: A tuple containing the public key and private key.
    """

    print("GENERATING KEYS")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

