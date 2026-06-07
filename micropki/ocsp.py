# micropki/ocsp.py
import datetime
from asn1crypto import ocsp as asn1_ocsp, x509 as asn1_x509, core, algos
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

# ---------- Helper functions for issuer hashes (не меняются) ----------
def compute_issuer_name_hash(cert):
    der = cert.subject.public_bytes(serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA1())
    digest.update(der)
    return digest.finalize()

def compute_issuer_key_hash(cert):
    pubkey_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Извлекаем BIT STRING
    bit_string_pos = pubkey_der.find(b'\x03')
    if bit_string_pos == -1:
        raise ValueError("Cannot locate BIT STRING")
    length_byte = pubkey_der[bit_string_pos + 1]
    if length_byte & 0x80:
        len_bytes = length_byte & 0x7F
        total_len = int.from_bytes(pubkey_der[bit_string_pos+2:bit_string_pos+2+len_bytes], 'big')
        data_start = bit_string_pos + 2 + len_bytes + 1
    else:
        total_len = length_byte
        data_start = bit_string_pos + 2 + 1
    key_bytes = pubkey_der[data_start:data_start + total_len - 1]
    digest = hashes.Hash(hashes.SHA1())
    digest.update(key_bytes)
    return digest.finalize()

def _reason_str_to_flag(reason_str):
    mapping = {
        'unspecified': x509.ReasonFlags.unspecified,
        'keyCompromise': x509.ReasonFlags.key_compromise,
        'cACompromise': x509.ReasonFlags.ca_compromise,
        'affiliationChanged': x509.ReasonFlags.affiliation_changed,
        'superseded': x509.ReasonFlags.superseded,
        'cessationOfOperation': x509.ReasonFlags.cessation_of_operation,
        'certificateHold': x509.ReasonFlags.certificate_hold,
        'removeFromCRL': x509.ReasonFlags.remove_from_crl,
        'privilegeWithdrawn': x509.ReasonFlags.privilege_withdrawn,
        'aACompromise': x509.ReasonFlags.aa_compromise,
    }
    return mapping.get(reason_str, x509.ReasonFlags.unspecified)

# ---------- Парсинг запроса (оставляем asn1crypto для совместимости) ----------
def parse_ocsp_request(request_der):
    try:
        ocsp_req = asn1_ocsp.OCSPRequest.load(request_der)
    except Exception:
        return None, None
    tbs_request = ocsp_req['tbs_request']
    request_list = tbs_request['request_list']
    cert_ids = []
    for req in request_list:
        req_cert = req['req_cert']
        issuer_name_hash = req_cert['issuer_name_hash'].native
        issuer_key_hash = req_cert['issuer_key_hash'].native
        serial_raw = req_cert['serial_number'].native
        if isinstance(serial_raw, int):
            serial_number = serial_raw
        elif isinstance(serial_raw, bytes):
            serial_number = int.from_bytes(serial_raw, byteorder='big')
        else:
            serial_number = int(serial_raw)
        class SimpleCertID:
            pass
        cid = SimpleCertID()
        cid.issuer_name_hash = issuer_name_hash
        cid.issuer_key_hash = issuer_key_hash
        cid.serial_number = serial_number
        cert_ids.append(cid)
    nonce = None
    extensions = tbs_request['request_extensions']
    if extensions:
        for ext in extensions:
            if ext['extn_id'].native == 'nonce':
                nonce = ext['extn_value'].native
                break
    return cert_ids, nonce

# ---------- Построение ответа через cryptography.x509.ocsp ----------
def build_ocsp_response_der(cert, issuer_cert, status, this_update, next_update,
                            revocation_time, revocation_reason, responder_cert, responder_key,
                            nonce=None):
    from cryptography.x509 import ocsp
    from cryptography.hazmat.primitives import hashes

    builder = ocsp.OCSPResponseBuilder()

    if status == 'good':
        cert_status = ocsp.OCSPCertStatus.GOOD
    elif status == 'revoked':
        cert_status = ocsp.OCSPCertStatus.REVOKED
        if isinstance(revocation_reason, str):
            revocation_reason = _reason_str_to_flag(revocation_reason)
    else:
        cert_status = ocsp.OCSPCertStatus.UNKNOWN

    builder = builder.add_response(
        cert=cert,
        issuer=issuer_cert,
        algorithm=hashes.SHA256(),
        cert_status=cert_status,
        this_update=this_update,
        next_update=next_update,
        revocation_time=revocation_time if status == 'revoked' else None,
        revocation_reason=revocation_reason if status == 'revoked' else None
    )

    builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    builder = builder.certificates([responder_cert, issuer_cert])

    if nonce:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)

    response = builder.sign(responder_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)