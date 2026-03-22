import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

def generate_rsa_key():
    """Generate 4096-bit RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

def generate_ecc_key():
    """Generate P-384 ECC private key."""
    return ec.generate_private_key(
        ec.SECP384R1(),
        backend=default_backend()
    )

def encrypt_private_key(private_key, passphrase):
    """Encrypt private key with passphrase and return PEM bytes (PKCS#8)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )

def load_encrypted_private_key(pem_data, passphrase):
    """Load encrypted private key from PEM bytes."""
    return serialization.load_pem_private_key(
        pem_data,
        password=passphrase,
        backend=default_backend()
    )