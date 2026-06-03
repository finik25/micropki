# micropki/revocation.py
import datetime
from . import database
from .logger import setup_logging

# Сопоставление строковых причин с кодами ASN.1 (RFC 5280)
REASON_CODES = {
    'unspecified': 0,
    'keycompromise': 1,   # было keyCompromise
    'cacompromise': 2,    # было cACompromise
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
        # Для пользователя показываем исходные названия (с учётом регистра из требований)
        supported = ['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                     'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL',
                     'privilegeWithdrawn', 'aACompromise']
        raise ValueError(f"Unsupported revocation reason: {reason_str}. "
                         f"Supported: {', '.join(supported)}")
    return REASON_CODES[key]

def revoke_certificate(db_path, serial_hex, reason=None, force=False, log_file=None, log_format='text'):
    """Отозвать сертификат по серийному номеру (с префиксом 0x или без)."""
    logger = setup_logging(log_file, log_format=log_format)
    # Нормализуем серийный номер
    if not serial_hex.startswith('0x'):
        serial_hex = '0x' + serial_hex
    cert_data = database.get_cert_by_serial(db_path, serial_hex)
    if not cert_data:
        logger.error(f"Certificate with serial {serial_hex} not found")
        raise ValueError(f"Certificate with serial {serial_hex} not found")
    if cert_data['status'] == 'revoked':
        logger.warning(f"Certificate {serial_hex} is already revoked")
        return  # ничего не делаем
    # Если не force и сертификат уже недействителен, можно предупредить, но по заданию force не обязателен
    # Просто выполняем отзыв
    reason_code = reason_to_code(reason) if reason else None
    rev_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
    database.update_cert_status(db_path, serial_hex, 'revoked', reason=reason, date=rev_date)
    logger.info(f"Certificate {serial_hex} revoked, reason={reason}, date={rev_date}")
    # Дополнительно: при желании можно автоматически генерировать CRL, но по требованию – нет
    return