# micropki/client.py
import os
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from .certificates import parse_dn, parse_san, create_csr
from .ca import verify_chain
from .revocation_check import check_status, extract_ocsp_uri, extract_crl_uris


def generate_csr(subject, key_type='rsa', key_size=2048, san_list=None,
                 out_key=None, out_csr=None, force=False):
    if out_key is None:
        out_key = Path.cwd() / 'key.pem'
    if out_csr is None:
        out_csr = Path.cwd() / 'request.csr.pem'

    out_key = Path(out_key)
    out_csr = Path(out_csr)

    if not force:
        if out_key.exists():
            raise FileExistsError(f"Private key file already exists: {out_key}")
        if out_csr.exists():
            raise FileExistsError(f"CSR file already exists: {out_csr}")

    if key_type == 'rsa':
        if key_size not in (2048, 4096):
            raise ValueError("RSA key size must be 2048 or 4096")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    elif key_type == 'ecc':
        if key_size not in (256, 384):
            raise ValueError("ECC key size must be 256 or 384")
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1()}
        private_key = ec.generate_private_key(curves[key_size], default_backend())
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    out_key.write_bytes(key_pem)
    if os.name == 'posix':
        os.chmod(out_key, 0o600)

    san_objects = parse_san(san_list) if san_list else []
    csr = _build_csr(subject, private_key, san_objects)
    out_csr.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    return out_key, out_csr


def _build_csr(subject_dn, private_key, san_list):
    extensions = []
    if san_list:
        extensions.append(x509.Extension(
            oid=x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName(san_list)
        ))
    return create_csr(subject_dn, private_key, extensions=extensions)


def request_cert(csr_path, template, ca_url, out_cert=None, force=False):
    if out_cert is None:
        out_cert = Path.cwd() / 'cert.pem'
    out_cert = Path(out_cert)

    if not force and out_cert.exists():
        raise FileExistsError(f"Certificate file already exists: {out_cert}")

    with open(csr_path, 'rb') as f:
        csr_pem = f.read()

    url = f"{ca_url.rstrip('/')}/request-cert"
    params = {'template': template}
    headers = {'Content-Type': 'application/x-pem-file'}
    resp = requests.post(url, params=params, data=csr_pem, headers=headers)

    if resp.status_code != 201:
        raise RuntimeError(f"Certificate request failed: {resp.status_code} {resp.text}")

    out_cert.write_bytes(resp.content)
    return out_cert


def validate_cert(cert_path, intermediates=None, trust_store=None,
                  crl_source=None, ocsp_source=None, mode='full'):
    # Load leaf certificate
    with open(cert_path, 'rb') as f:
        leaf_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    leaf_path = cert_path
    root_path = trust_store if trust_store else None
    intermediate_path = intermediates[0] if intermediates else None

    valid, msg = verify_chain(leaf_path, root_path, intermediate_path)
    if not valid:
        return {'valid': False, 'message': msg, 'chain_result': msg}

    if mode == 'full':
        issuer_path = intermediate_path if intermediate_path else root_path
        if not issuer_path:
            return {'valid': False, 'message': 'No issuer certificate provided for revocation check'}
        with open(issuer_path, 'rb') as f:
            issuer_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        ocsp_url = ocsp_source if ocsp_source else extract_ocsp_uri(leaf_cert)
        crl = crl_source if crl_source else (extract_crl_uris(leaf_cert)[0] if extract_crl_uris(leaf_cert) else None)

        status_info = check_status(leaf_cert, issuer_cert, crl_source=crl, ocsp_url=ocsp_url)

        if status_info['status'] == 'revoked':
            return {
                'valid': False,
                'message': f"Certificate is REVOKED. Reason: {status_info['reason']}, Date: {status_info['revocation_time']}",
                'status': status_info
            }
        elif status_info['status'] == 'unknown':
            return {
                'valid': False,
                'message': f"Revocation status unknown: {status_info.get('reason', 'No valid OCSP/CRL response')}",
                'status': status_info
            }
        else:
            return {'valid': True, 'message': 'Chain valid and not revoked', 'status': status_info}
    else:
        return {'valid': True, 'message': 'Chain valid (revocation not checked)'}


def check_status_cli(cert_path, ca_cert_path, crl_source=None, ocsp_url=None):
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_cert_path, 'rb') as f:
        issuer = x509.load_pem_x509_certificate(f.read(), default_backend())
    return check_status(cert, issuer, crl_source=crl_source, ocsp_url=ocsp_url)