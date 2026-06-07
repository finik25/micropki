# micropki/revocation_check.py
import os
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import OCSPNonce
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
import cryptography.x509.ocsp


def extract_ocsp_uri(cert):
    """Extract OCSP responder URL from Authority Information Access extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access in aia.value:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                return access.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def extract_crl_uris(cert):
    """Extract CRL distribution point URLs from CRL Distribution Points extension."""
    uris = []
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for point in cdp.value:
            for name in point.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    uris.append(name.value)
    except x509.ExtensionNotFound:
        pass
    return uris


def query_ocsp(issuer_cert, subject_cert, responder_url=None, nonce=True):
    """
    Query OCSP responder for certificate status.
    Returns dict: {'status': 'good'|'revoked'|'unknown', 'reason': str, 'revocation_time': datetime}
    """
    if responder_url is None:
        responder_url = extract_ocsp_uri(subject_cert)
        if not responder_url:
            raise ValueError("No OCSP responder URL found in certificate")

    builder = cryptography.x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(subject_cert, issuer_cert, hashes.SHA256())
    if nonce:
        nonce_value = os.urandom(16)
        builder = builder.add_extension(OCSPNonce(nonce_value), critical=False)

    request = builder.build()
    data = request.public_bytes(serialization.Encoding.DER)

    headers = {'Content-Type': 'application/ocsp-request'}
    resp = requests.post(responder_url, data=data, headers=headers, timeout=10)

    if resp.status_code != 200:
        raise RuntimeError(f"OCSP request failed with HTTP {resp.status_code}")

    ocsp_response = cryptography.x509.ocsp.load_der_ocsp_response(resp.content)

    if ocsp_response.response_status != cryptography.x509.ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise RuntimeError(f"OCSP response status: {ocsp_response.response_status}")

    responses = ocsp_response.responses
    if not responses:
        raise RuntimeError("OCSP response contains no certificate status")

    single_response = responses[0]
    status = single_response.certificate_status
    status_str = status.name.lower()
    result = {'status': status_str, 'reason': None, 'revocation_time': None}
    if status_str == 'revoked':
        result['revocation_time'] = single_response.revocation_time
        for ext in single_response.extensions:
            if ext.oid.dotted_string == '2.5.29.21':  # CRLReason
                result['reason'] = ext.value.reason.name if hasattr(ext.value, 'reason') else str(ext.value)
    return result


def fetch_crl(source):
    """
    Load CRL from file or URL.
    Returns cryptography.x509.CertificateRevocationList.
    """
    if source.startswith(('http://', 'https://')):
        resp = requests.get(source, timeout=10)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch CRL from {source}: HTTP {resp.status_code}")
        crl_data = resp.content
    else:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"CRL file not found: {source}")
        with open(path, 'rb') as f:
            crl_data = f.read()
    try:
        return x509.load_pem_x509_crl(crl_data, default_backend())
    except ValueError:
        return x509.load_der_x509_crl(crl_data, default_backend())


def check_crl(cert, crl):
    """
    Check if certificate serial is in CRL.
    Returns dict: {'status': 'good' or 'revoked', 'reason': str, 'revocation_time': datetime}
    """
    serial = cert.serial_number
    for revoked in crl:
        if revoked.serial_number == serial:
            reason = None
            for ext in revoked.extensions:
                if ext.oid.dotted_string == '2.5.29.21':
                    reason = ext.value.reason.name if hasattr(ext.value, 'reason') else str(ext.value)
            return {
                'status': 'revoked',
                'reason': reason,
                'revocation_time': revoked.revocation_date
            }
    return {'status': 'good', 'reason': None, 'revocation_time': None}


def check_status(cert, issuer_cert, crl_source=None, ocsp_url=None):
    """
    Check revocation status using OCSP first, fallback to CRL.
    Returns dict with status, reason, revocation_time.
    """
    # Try OCSP first
    try:
        url = ocsp_url if ocsp_url else extract_ocsp_uri(cert)
        if url:
            result = query_ocsp(issuer_cert, cert, responder_url=url)
            if result['status'] in ('good', 'revoked'):
                return result
    except Exception:
        # OCSP failed, continue to CRL
        pass

    # Fallback to CRL
    try:
        if crl_source:
            crl = fetch_crl(crl_source)
        else:
            uris = extract_crl_uris(cert)
            if not uris:
                raise ValueError("No CRL source provided and no CDP in certificate")
            crl = fetch_crl(uris[0])
        return check_crl(cert, crl)
    except Exception as e:
        return {'status': 'unknown', 'reason': str(e), 'revocation_time': None}