import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def parse_dn(dn_string):
    """
    Convert DN string to x509.Name.
    Supports formats:
        "/CN=Root CA/O=Demo/C=US"
        "CN=Root CA,O=Demo,C=US"
    """
    dn_string = dn_string.strip()
    if dn_string.startswith('/'):
        parts = dn_string.split('/')[1:]  # first element is empty
    else:
        parts = dn_string.split(',')
    attributes = []
    for part in parts:
        part = part.strip()
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        key = key.strip().upper()
        value = value.strip()
        oid_map = {
            'CN': NameOID.COMMON_NAME,
            'O': NameOID.ORGANIZATION_NAME,
            'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'C': NameOID.COUNTRY_NAME,
            'ST': NameOID.STATE_OR_PROVINCE_NAME,
            'L': NameOID.LOCALITY_NAME,
            'STREET': NameOID.STREET_ADDRESS,
            'EMAIL': NameOID.EMAIL_ADDRESS
        }
        oid = oid_map.get(key)
        if oid:
            attributes.append(x509.NameAttribute(oid, value))
    return x509.Name(attributes)

def generate_serial_number():
    """Generate a random 152-bit serial number (19 bytes)."""
    return int.from_bytes(os.urandom(19), byteorder='big')

def create_self_signed_cert(subject_dn, private_key, validity_days, key_type):
    """Create a self-signed X.509 certificate."""
    subject = parse_dn(subject_dn)
    issuer = subject
    serial = generate_serial_number()
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now
    not_after = now + datetime.timedelta(days=validity_days)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.public_key(private_key.public_key())

    # Basic Constraints: CA=True, critical
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    # Key Usage: keyCertSign, cRLSign
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    # Authority Key Identifier (self-signed)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        ),
        critical=False
    )

    # Signature hash based on key type
    if key_type == 'rsa':
        signature_hash = hashes.SHA256()
    else:  # ecc
        signature_hash = hashes.SHA384()

    certificate = builder.sign(
        private_key=private_key,
        algorithm=signature_hash,
        backend=default_backend()
    )
    return certificate