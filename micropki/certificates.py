import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    AuthorityInformationAccess, AccessDescription,
    CRLDistributionPoints, DistributionPoint,
    UniformResourceIdentifier
)


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


def build_cdp_extension(crl_urls):
    """Build CRL Distribution Points extension from list of URLs."""
    if not crl_urls:
        return None
    points = []
    for url in crl_urls:
        point = DistributionPoint(
            full_name=[UniformResourceIdentifier(url)],
            relative_name=None,
            reasons=None,
            crl_issuer=None
        )
        points.append(point)
    return CRLDistributionPoints(points)


def build_aia_extension(ocsp_url):
    """Build Authority Information Access extension with OCSP responder URL."""
    if not ocsp_url:
        return None
    access_desc = AccessDescription(
        access_method=AuthorityInformationAccessOID.OCSP,
        access_location=UniformResourceIdentifier(ocsp_url)
    )
    return AuthorityInformationAccess([access_desc])


def apply_template(template_name, public_key, san_list, crl_urls=None, ocsp_url=None):
    if template_name not in ('server', 'client', 'code_signing', 'ocsp_signer'):
        raise ValueError(f"Unknown template: {template_name}")

    extensions = []
    basic = x509.BasicConstraints(ca=False, path_length=None)
    extensions.append(x509.Extension(
        oid=x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
        critical=True,
        value=basic
    ))

    key_usage = None
    ext_key_usage = None

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

    elif template_name == 'code_signing':
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        )
        ext_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        for san in san_list:
            if not isinstance(san, (x509.DNSName, x509.UniformResourceIdentifier)):
                raise ValueError("Code signing certificate only allows DNS or URI SANs")

    elif template_name == 'ocsp_signer':
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False
        )
        ocsp_signing_oid = ObjectIdentifier("1.3.6.1.5.5.7.3.9")
        ext_key_usage = x509.ExtendedKeyUsage([ocsp_signing_oid])

    if key_usage is not None:
        extensions.append(x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=key_usage
        ))
    if ext_key_usage is not None:
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

    if crl_urls:
        cdp_ext = build_cdp_extension(crl_urls)
        if cdp_ext:
            extensions.append(x509.Extension(
                oid=x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS,
                critical=False,
                value=cdp_ext
            ))
    if ocsp_url:
        aia_ext = build_aia_extension(ocsp_url)
        if aia_ext:
            extensions.append(x509.Extension(
                oid=x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=False,
                value=aia_ext
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


def sign_csr(csr, ca_cert, ca_private_key, validity_days, template_name, san_strings=None,
             serial_number=None, crl_urls=None, ocsp_url=None):
    san_list = parse_san(san_strings) if san_strings else []
    public_key = csr.public_key()
    template_extensions = apply_template(template_name, public_key, san_list, crl_urls, ocsp_url)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
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


def create_intermediate_certificate(subject_dn, public_key, ca_cert, ca_private_key, validity_days,
                                    pathlen=0, serial_number=None, crl_urls=None, ocsp_url=None):
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
    if crl_urls:
        cdp_ext = build_cdp_extension(crl_urls)
        if cdp_ext:
            builder = builder.add_extension(cdp_ext, critical=False)
    if ocsp_url:
        aia_ext = build_aia_extension(ocsp_url)
        if aia_ext:
            builder = builder.add_extension(aia_ext, critical=False)
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


# ========== Политики безопасности ==========
from .config import POLICY_MAX_VALIDITY_DAYS, POLICY_MIN_KEY_SIZE, POLICY_FORBIDDEN_WILDCARD, POLICY_ALLOWED_SAN_TYPES

def check_validity_period(cert_type: str, validity_days: int) -> None:
    """Проверить, что срок действия не превышает максимум."""
    max_days = POLICY_MAX_VALIDITY_DAYS.get(cert_type)
    if max_days is None:
        raise ValueError(f"Unknown certificate type: {cert_type}")
    if validity_days > max_days:
        raise ValueError(f"Validity period {validity_days} days exceeds maximum {max_days} days for {cert_type} certificate")

def check_key_size(key_type: str, key_size: int, cert_type: str) -> None:
    """Проверить, что размер ключа соответствует минимальным требованиям."""
    if key_type == 'rsa':
        min_size = POLICY_MIN_KEY_SIZE.get(f'rsa_{cert_type}')
        if min_size is None:
            min_size = POLICY_MIN_KEY_SIZE['rsa_end_entity']
        if key_size < min_size:
            raise ValueError(f"RSA key size {key_size} is below minimum {min_size} for {cert_type} certificate")
    elif key_type == 'ecc':
        min_size = POLICY_MIN_KEY_SIZE.get(f'ecc_{cert_type}')
        if min_size is None:
            min_size = POLICY_MIN_KEY_SIZE['ecc_end_entity']
        if key_size < min_size:
            raise ValueError(f"ECC key size {key_size} is below minimum {min_size} for {cert_type} certificate")
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

def check_san_types(template: str, san_list) -> None:
    """
    Проверить, что типы SAN соответствуют разрешённым для шаблона.
    san_list – список объектов GeneralName (DNSName, IPAddress, RFC822Name, URI)
    """
    allowed = POLICY_ALLOWED_SAN_TYPES.get(template, set())
    if not allowed:
        return  # нет ограничений
    for san in san_list:
        if isinstance(san, x509.DNSName):
            typ = 'dns'
            if POLICY_FORBIDDEN_WILDCARD and '*' in san.value:
                raise ValueError(f"Wildcard DNS name '{san.value}' is forbidden for {template} certificate")
        elif isinstance(san, x509.IPAddress):
            typ = 'ip'
        elif isinstance(san, x509.RFC822Name):
            typ = 'email'
        elif isinstance(san, x509.UniformResourceIdentifier):
            typ = 'uri'
        else:
            typ = 'unknown'
        if typ not in allowed:
            raise ValueError(f"SAN type '{typ}' is not allowed for {template} certificate. Allowed: {allowed}")