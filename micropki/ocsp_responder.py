# micropki/ocsp_responder.py
import datetime
import os
import logging
import threading
from flask import Flask, request, Response
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from . import database, ocsp
from .logger import setup_logging

# Простой кэш с TTL
class OCSPCache:
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._cache.get(key)
            if entry and entry['expires'] > datetime.datetime.now(datetime.timezone.utc):
                return entry['response']
            return None

    def set(self, key, response, ttl_seconds):
        with self._lock:
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl_seconds)
            self._cache[key] = {'response': response, 'expires': expires}
            # Очистка: удаляем просроченные записи (опционально, можно не делать часто)
            self._cleanup()

    def _cleanup(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        expired_keys = [k for k, v in self._cache.items() if v['expires'] <= now]
        for k in expired_keys:
            del self._cache[k]

# Глобальный экземпляр кэша (будет создан при первом вызове create_ocsp_app)
_cache = None

def create_ocsp_app(db_path, responder_cert_path, responder_key_path, ca_cert_path,
                    cache_ttl=60, log_file=None, log_format='text'):
    global _cache
    if _cache is None:
        _cache = OCSPCache()

    # Проверяем существование файлов
    for path in [responder_cert_path, responder_key_path, ca_cert_path]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Required OCSP file not found: {path}")

    # Загружаем сертификаты и ключ
    try:
        with open(responder_cert_path, 'rb') as f:
            responder_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(responder_key_path, 'rb') as f:
            responder_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    except Exception as e:
        raise RuntimeError(f"Failed to load OCSP certificates/keys: {e}") from e

    app = Flask(__name__)
    app.config['DB_PATH'] = db_path
    app.config['CACHE_TTL'] = cache_ttl
    app.config['RESPONDER_CERT'] = responder_cert
    app.config['RESPONDER_KEY'] = responder_key
    app.config['CA_CERT'] = ca_cert
    app.config['ISSUER_NAME_HASH'] = ocsp.compute_issuer_name_hash(ca_cert)
    app.config['ISSUER_KEY_HASH'] = ocsp.compute_issuer_key_hash(ca_cert)

    # Настройка логгера
    logger = setup_logging(log_file, log_format=log_format, logger_name='micropki.ocsp')
    app.logger.handlers = []
    for handler in logger.handlers:
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.route('/ocsp', methods=['POST'])
    def ocsp_endpoint():
        if request.content_type != 'application/ocsp-request':
            app.logger.warning(f"Invalid Content-Type: {request.content_type}")
            return Response(b'Bad Request', status=400, mimetype='text/plain')

        request_der = request.data
        app.logger.info(f"Received OCSP request, length={len(request_der)}")

        cert_ids, nonce = ocsp.parse_ocsp_request(request_der)
        if cert_ids is None:
            app.logger.error("Failed to parse OCSP request")
            return Response(b'Malformed Request', status=400, mimetype='text/plain')
        if not cert_ids:
            return Response(b'No certificate IDs', status=400)

        cert_id = cert_ids[0]
        serial_hex = hex(cert_id.serial_number)
        app.logger.info(f"Looking up serial: {serial_hex}")

        # Кэширование: ключ = (serial_hex, nonce)
        cache_key = (serial_hex, nonce if nonce else b'')
        cached_response = _cache.get(cache_key)
        if cached_response:
            app.logger.info(f"Cache hit for {serial_hex}, nonce={bool(nonce)}")
            return Response(cached_response, mimetype='application/ocsp-response')

        # Проверка наличия сертификата в БД
        cert_by_serial = database.get_cert_by_serial(app.config['DB_PATH'], serial_hex)
        if cert_by_serial is None:
            app.logger.error(f"Certificate {serial_hex} not found in database at all")
        else:
            app.logger.info(f"Found in DB: serial={serial_hex}, issuer='{cert_by_serial['issuer']}', status={cert_by_serial['status']}")

        issuer_dn_str = app.config['CA_CERT'].subject.rfc4514_string()
        app.logger.info(f"Looking for certificate with issuer DN: '{issuer_dn_str}'")

        cert_obj = database.get_cert_object_by_serial(app.config['DB_PATH'], serial_hex)

        if cert_obj is None:
            app.logger.info(f"Certificate {serial_hex} not found or issuer mismatch")
            return Response(b'Not Found', status=404)

        cert_data = database.get_cert_by_serial(app.config['DB_PATH'], serial_hex)
        if cert_data['status'] == 'revoked':
            status = 'revoked'
            rev_time = datetime.datetime.fromisoformat(cert_data['revocation_date'])
            rev_reason = cert_data['revocation_reason']
        else:
            status = 'good'
            rev_time = None
            rev_reason = None

        try:
            der_response = ocsp.build_ocsp_response_der(
                cert=cert_obj,
                issuer_cert=app.config['CA_CERT'],
                status=status,
                this_update=datetime.datetime.now(datetime.timezone.utc),
                next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=app.config['CACHE_TTL']),
                revocation_time=rev_time,
                revocation_reason=rev_reason,
                responder_cert=app.config['RESPONDER_CERT'],
                responder_key=app.config['RESPONDER_KEY'],
                nonce=nonce
            )
            # Сохраняем в кэш
            _cache.set(cache_key, der_response, app.config['CACHE_TTL'])
            app.logger.info(f"OCSP response: serial={serial_hex}, status={status}")
            return Response(der_response, mimetype='application/ocsp-response')
        except Exception as e:
            app.logger.error(f"Failed to build OCSP response: {e}")
            import traceback
            traceback.print_exc()
            return Response(b'Internal Error', status=500, mimetype='text/plain')

    return app