# micropki/revocation.py
import datetime
from pathlib import Path

from . import database
from .logger import setup_logging
from .audit import get_audit_logger

REASON_CODES = {
    'unspecified': 0,
    'keycompromise': 1,
    'cacompromise': 2,
    'affiliationchanged': 3,
    'superseded': 4,
    'cessationofoperation': 5,
    'certificatehold': 6,
    'removefromcrl': 8,
    'privilegewithdrawn': 9,
    'aacompromise': 10,
}

def reason_to_code(reason_str):
    if reason_str is None:
        return None
    key = reason_str.lower()
    if key not in REASON_CODES:
        supported = ['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                     'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL',
                     'privilegeWithdrawn', 'aACompromise']
        raise ValueError(f"Unsupported revocation reason: {reason_str}. "
                         f"Supported: {', '.join(supported)}")
    return REASON_CODES[key]

def revoke_certificate(db_path, serial_hex, reason=None, force=False, log_file=None, log_format='text'):
    from .audit import ensure_audit
    # pki_dir – получаем из db_path
    pki_dir = Path(db_path).parent
    ensure_audit(pki_dir)
    logger = setup_logging(log_file, log_format=log_format)
    if not serial_hex.startswith('0x'):
        serial_hex = '0x' + serial_hex
    cert_data = database.get_cert_by_serial(db_path, serial_hex)
    if not cert_data:
        logger.error(f"Certificate with serial {serial_hex} not found")
        raise ValueError(f"Certificate with serial {serial_hex} not found")
    if cert_data['status'] == 'revoked':
        logger.warning(f"Certificate {serial_hex} is already revoked")
        # Audit: already revoked
        audit = get_audit_logger()
        audit.log('WARNING', 'revoke', 'already_revoked',
                  f"Certificate {serial_hex} already revoked", {'serial': serial_hex})
        return
    reason_code = reason_to_code(reason) if reason else None
    rev_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
    database.update_cert_status(db_path, serial_hex, 'revoked', reason=reason, date=rev_date)
    logger.info(f"Certificate {serial_hex} revoked, reason={reason}, date={rev_date}")

    # Audit success
    audit = get_audit_logger()
    audit.log('AUDIT', 'revoke', 'success',
              f"Certificate {serial_hex} revoked, reason={reason}",
              {'serial': serial_hex, 'reason': reason, 'date': rev_date})
    return