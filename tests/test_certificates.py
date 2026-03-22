import pytest
from cryptography import x509
from micropki.certificates import parse_dn, generate_serial_number, create_self_signed_cert
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key

def test_parse_dn_slash():
    dn = parse_dn("/CN=Root CA/O=Demo/C=US")
    assert len(dn) == 3
    # Check order is preserved? Not necessary for test

def test_parse_dn_comma():
    dn = parse_dn("CN=Root CA,O=Demo,C=US")
    assert len(dn) == 3

def test_serial_number():
    sn = generate_serial_number()
    assert sn > 0
    # Ensure it's 160 bits (max ~ 2^160)
    assert sn.bit_length() <= 160

def test_create_self_signed_rsa():
    key = generate_rsa_key()
    cert = create_self_signed_cert("CN=Test CA", key, 365, "rsa")
    assert cert.subject == cert.issuer
    # Check extensions
    basic = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    assert basic.value.ca is True
    assert basic.critical is True

    key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.crl_sign is True
    assert key_usage.critical is True

    ski = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    aki = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    assert ski.value.digest == aki.value.key_identifier

def test_create_self_signed_ecc():
    key = generate_ecc_key()
    cert = create_self_signed_cert("CN=Test ECC CA", key, 365, "ecc")
    # Basic checks
    assert cert.signature_algorithm_oid._name == "ecdsa-with-SHA384"