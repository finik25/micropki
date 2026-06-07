# micropki/crl.py
import datetime
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from . import database, crypto_utils
from .revocation import REASON_CODES
from .logger import setup_logging
from .audit import get_audit_logger


def generate_crl(db_path, ca_cert_path, ca_key_path, ca_pass_file, out_file,
                 next_update_days=7, log_file=None, log_format='text'):
    from .audit import ensure_audit
    pki_dir = Path(db_path).parent
    ensure_audit(pki_dir)
    logger = setup_logging(log_file, log_format=log_format)

    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_key_path, 'rb') as f:
        ca_key_data = f.read()
    with open(ca_pass_file, 'rb') as f:
        ca_pass = f.read().strip()
    ca_private_key = serialization.load_pem_private_key(ca_key_data, ca_pass, default_backend())

    ca_subject = ca_cert.subject.rfc4514_string()
    revoked_certs_data = database.get_revoked_certs_for_issuer(db_path, ca_subject)

    revoked_list = []
    for r in revoked_certs_data:
        serial = int(r['serial_hex'], 16)
        rev_date = datetime.datetime.fromisoformat(r['revocation_date'])
        builder = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(rev_date)
        reason_str = r.get('revocation_reason')
        if reason_str:
            reason_flag = getattr(x509.ReasonFlags, reason_str, None)
            if reason_flag is not None:
                builder = builder.add_extension(
                    x509.CRLReason(reason_flag),
                    critical=False
                )
        revoked_list.append(builder.build())

    crl_number = database.get_next_crl_number(db_path, ca_subject)
    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(days=next_update_days)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(next_update)
    for revoked in revoked_list:
        builder = builder.add_revoked_certificate(revoked)

    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False
    )
    aki_extension = ca_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    )
    builder = builder.add_extension(
        aki_extension.value,
        critical=False
    )

    if isinstance(ca_private_key, rsa.RSAPrivateKey):
        signature_hash = hashes.SHA256()
    elif isinstance(ca_private_key, ec.EllipticCurvePrivateKey):
        signature_hash = hashes.SHA384()
    else:
        signature_hash = hashes.SHA256()

    crl = builder.sign(ca_private_key, signature_hash, default_backend())

    out_path = Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Generated CRL for {ca_subject}: number={crl_number}, "
                f"revoked_count={len(revoked_list)}, thisUpdate={now}, nextUpdate={next_update}")

    database.update_crl_metadata(
        db_path, ca_subject, crl_number,
        now.isoformat(), next_update.isoformat(), str(out_path)
    )

    # Audit
    audit = get_audit_logger()
    audit.log('AUDIT', 'gen_crl', 'success',
              f"Generated CRL for {ca_subject}, number={crl_number}, revoked_count={len(revoked_list)}",
              {'ca_subject': ca_subject, 'crl_number': crl_number,
               'revoked_count': len(revoked_list), 'this_update': now.isoformat(),
               'next_update': next_update.isoformat(), 'crl_path': str(out_path)})

    return out_path