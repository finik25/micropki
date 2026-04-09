import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

def parse_dn(dn_string):
    dn_string = dn_string.strip()
    if dn_string.startswith('/'):
        parts = dn_string.split('/')[1:]
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
    """Legacy random serial generator (152-bit)."""
    return int.from_bytes(os.urandom(19), byteorder='big')

def parse_san(san_strings):
    san_list = []
    for s in san_strings:
        if ':' not in s:
            raise ValueError(f"Invalid SAN format: {s}. Expected 'type:value'")
        typ, val = s.split(':', 1)
        typ = typ.lower()
        if typ == 'dns':
            san_list.append(x509.DNSName(val))
        elif typ == 'ip':
            try:
                ip = ipaddress.ip_address(val)
                san_list.append(x509.IPAddress(ip))
            except ValueError:
                raise ValueError(f"Invalid IP address: {val}")
        elif typ == 'email':
            san_list.append(x509.RFC822Name(val))
        elif typ == 'uri':
            san_list.append(x509.UniformResourceIdentifier(val))
        else:
            raise ValueError(f"Unsupported SAN type: {typ}")
    return san_list

def apply_template(template_name, public_key, san_list):
    if template_name not in ('server', 'client', 'code_signing'):
        raise ValueError(f"Unknown template: {template_name}")
    extensions = []
    basic = x509.BasicConstraints(ca=False, path_length=None)
    extensions.append(x509.Extension(
        oid=x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
        critical=True,
        value=basic
    ))
    if template_name == 'server':
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        )
        ext_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        if not any(isinstance(san, (x509.DNSName, x509.IPAddress)) for san in san_list):
            raise ValueError("Server certificate must have at least one DNS or IP SAN")
    elif template_name == 'client':
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        )
        ext_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    else:  # code_signing
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        )
        ext_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        for san in san_list:
            if not isinstance(san, (x509.DNSName, x509.UniformResourceIdentifier)):
                raise ValueError("Code signing certificate only allows DNS or URI SANs")
    extensions.append(x509.Extension(
        oid=x509.oid.ExtensionOID.KEY_USAGE,
        critical=True,
        value=key_usage
    ))
    extensions.append(x509.Extension(
        oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
        critical=False,
        value=ext_key_usage
    ))
    if san_list:
        extensions.append(x509.Extension(
            oid=x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName(san_list)
        ))
    return extensions

def create_csr(subject_dn, private_key, extensions=None):
    subject = parse_dn(subject_dn)
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if extensions:
        for ext in extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr

def sign_csr(csr, ca_cert, ca_private_key, validity_days, template_name, san_strings=None, serial_number=None):
    san_list = parse_san(san_strings) if san_strings else []
    public_key = csr.public_key()
    template_extensions = apply_template(template_name, public_key, san_list)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
    # Use provided serial or generate random
    serial = serial_number if serial_number is not None else generate_serial_number()
    builder = builder.serial_number(serial)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=validity_days))
    builder = builder.public_key(public_key)
    for ext in template_extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        ca_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
    )
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(aki, critical=False)
    signature_hash = hashes.SHA256() if isinstance(ca_private_key, rsa.RSAPrivateKey) else hashes.SHA384()
    cert = builder.sign(ca_private_key, signature_hash, default_backend())
    return cert

def create_intermediate_certificate(subject_dn, public_key, ca_cert, ca_private_key, validity_days, pathlen=0, serial_number=None):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(parse_dn(subject_dn))
    builder = builder.issuer_name(ca_cert.subject)
    serial = serial_number if serial_number is not None else generate_serial_number()
    builder = builder.serial_number(serial)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=validity_days))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ),
        critical=True
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        ca_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
    )
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(aki, critical=False)
    signature_hash = hashes.SHA256() if isinstance(ca_private_key, rsa.RSAPrivateKey) else hashes.SHA384()
    cert = builder.sign(ca_private_key, signature_hash, default_backend())
    return cert

def create_self_signed_cert(subject_dn, private_key, validity_days, key_type, serial_number=None):
    subject = parse_dn(subject_dn)
    issuer = subject
    serial = serial_number if serial_number is not None else generate_serial_number()
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
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        ),
        critical=False
    )
    if key_type == 'rsa':
        signature_hash = hashes.SHA256()
    else:
        signature_hash = hashes.SHA384()
    certificate = builder.sign(
        private_key=private_key,
        algorithm=signature_hash,
        backend=default_backend()
    )
    return certificate