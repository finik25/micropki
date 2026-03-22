import pytest
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key, encrypt_private_key, load_encrypted_private_key

def test_generate_rsa_key():
    key = generate_rsa_key()
    assert key.key_size == 4096

def test_generate_ecc_key():
    key = generate_ecc_key()
    # Check curve
    from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
    assert key.curve.name == SECP384R1().name

def test_encrypt_decrypt():
    key = generate_rsa_key()
    passphrase = b"secret"
    encrypted = encrypt_private_key(key, passphrase)
    decrypted = load_encrypted_private_key(encrypted, passphrase)
    assert decrypted.private_numbers() == key.private_numbers()