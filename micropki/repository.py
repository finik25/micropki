import os
import tempfile
from pathlib import Path
from flask import Flask, abort, request, Response
import logging
import json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from . import database, ca


def find_cert_in_fs(certs_dir, serial_hex):
    """Search for a certificate by serial number in the certs directory."""
    try:
        serial_int = int(serial_hex, 16)
    except ValueError:
        return None
    for fname in os.listdir(certs_dir):
        if fname.endswith(('.pem', '.crt', '.cert')):
            path = certs_dir / fname
            try:
                with open(path, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                if cert.serial_number == serial_int:
                    with open(path, 'rb') as f:
                        return f.read()
            except Exception:
                continue
    return None


def create_app(pki_dir, log_file=None, log_format='text',
               ca_cert_path=None, ca_key_path=None, ca_pass_file=None,
               crl_urls=None, ocsp_url=None):
    app = Flask(__name__)
    app.config['PKI_DIR'] = pki_dir
    app.config['CA_CERT_PATH'] = ca_cert_path
    app.config['CA_KEY_PATH'] = ca_key_path
    app.config['CA_PASS_FILE'] = ca_pass_file
    app.config['CRL_URLS'] = crl_urls          # изменено
    app.config['OCSP_URL'] = ocsp_url          # изменено

    db_path = Path(pki_dir) / 'micropki.db'
    certs_dir = Path(pki_dir) / 'certs'

    # Configure HTTP logger
    http_logger = logging.getLogger('micropki.http')
    if http_logger.handlers:
        http_logger.handlers.clear()
    http_logger.setLevel(logging.INFO)

    if log_format == 'json':
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                }
                if hasattr(record, 'method'):
                    log_entry['method'] = record.method
                if hasattr(record, 'path'):
                    log_entry['path'] = record.path
                if hasattr(record, 'client_ip'):
                    log_entry['client_ip'] = record.client_ip
                return json.dumps(log_entry)
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter('%(asctime)s.%(msecs)03d [HTTP] %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')

    if log_file:
        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    http_logger.addHandler(handler)

    @app.before_request
    def log_request():
        extra = {
            'method': request.method,
            'path': request.path,
            'client_ip': request.remote_addr
        }
        http_logger.info(f"{request.method} {request.path} - {request.remote_addr}", extra=extra)

    @app.route('/certificate/<serial>')
    def get_certificate(serial):
        try:
            int(serial, 16)
        except ValueError:
            abort(400, description="Invalid serial number format (must be hex)")
        if not database.db_exists(str(db_path)):
            abort(404, description="Database not found")
        serial_hex = serial if serial.startswith('0x') else '0x' + serial
        cert_data = database.get_cert_by_serial(str(db_path), serial_hex)
        if cert_data:
            return Response(cert_data['cert_pem'], mimetype='application/x-pem-file')
        # Fallback to filesystem search
        pem = find_cert_in_fs(certs_dir, serial)
        if pem:
            http_logger.info(f"Fallback: certificate {serial} found in filesystem (not in DB)")
            return Response(pem, mimetype='application/x-pem-file')
        abort(404, description="Certificate not found")

    @app.route('/ca/root')
    def get_root_ca():
        root_path = certs_dir / 'ca.cert.pem'
        if not root_path.exists():
            abort(404, description="Root CA certificate not found")
        try:
            with open(root_path, 'rb') as f:
                pem_data = f.read()
            return Response(pem_data, mimetype='application/x-pem-file')
        except Exception as e:
            http_logger.error(f"Error reading root CA cert: {e}")
            abort(500, description="Internal server error")

    @app.route('/ca/intermediate')
    def get_intermediate_ca():
        int_path = certs_dir / 'intermediate.cert.pem'
        if not int_path.exists():
            abort(404, description="Intermediate CA certificate not found")
        try:
            with open(int_path, 'rb') as f:
                pem_data = f.read()
            return Response(pem_data, mimetype='application/x-pem-file')
        except Exception as e:
            http_logger.error(f"Error reading intermediate CA cert: {e}")
            abort(500, description="Internal server error")

    @app.route('/crl')
    def get_crl():
        ca_param = request.args.get('ca', 'intermediate')  # по умолчанию intermediate
        if ca_param not in ('root', 'intermediate'):
            abort(400, description="ca parameter must be 'root' or 'intermediate'")
        crl_dir = Path(app.config.get('PKI_DIR', pki_dir)) / 'crl'
        crl_file = crl_dir / f'{ca_param}.crl.pem'
        if not crl_file.exists():
            abort(404, description=f"CRL for {ca_param} CA not found")
        # Отдаём с правильным Content-Type
        response = Response(crl_file.read_bytes(), mimetype='application/pkix-crl')
        # Добавляем кэширующие заголовки (опционально)
        mtime = os.path.getmtime(crl_file)
        response.headers['Last-Modified'] = datetime.fromtimestamp(mtime, timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        # max-age = nextUpdate - now (упрощённо: 1 час, можно вычислить из метаданных)
        # Для простоты ставим 3600 секунд
        response.headers['Cache-Control'] = 'max-age=3600'
        # ETag можно добавить, но не обязательно
        return response

    @app.route('/request-cert', methods=['POST'])
    def request_cert():
        template = request.args.get('template')
        if not template or template not in ('server', 'client', 'code_signing'):
            abort(400, description="Missing or invalid template parameter")
        csr_pem = request.data
        if not csr_pem:
            abort(400, description="Empty request body")
        ca_cert_path = app.config.get('CA_CERT_PATH')
        ca_key_path = app.config.get('CA_KEY_PATH')
        ca_pass_file = app.config.get('CA_PASS_FILE')
        if not all([ca_cert_path, ca_key_path, ca_pass_file]):
            abort(503, description="CA not configured for online signing")
        crl_urls = app.config.get('CRL_URLS')
        ocsp_url = app.config.get('OCSP_URL')
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csr', delete=False) as f:
            f.write(csr_pem)
            tmp_csr_path = f.name
        try:
            out_dir = Path(pki_dir) / 'certs'
            out_dir.mkdir(exist_ok=True)
            cert_path, _ = ca.issue_certificate(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_pass_file=ca_pass_file,
                template=template,
                subject=None,
                san_list=[],
                out_dir=str(out_dir),
                validity_days=365,
                csr_path=tmp_csr_path,
                pki_dir=pki_dir,
                force=True,
                crl_urls=crl_urls,
                ocsp_url=ocsp_url
            )
            with open(cert_path, 'rb') as f:
                cert_pem = f.read()
            return Response(cert_pem, status=201, mimetype='application/x-pem-file')
        except Exception as e:
            app.logger.error(f"Certificate issuance failed: {e}")
            abort(500, description=str(e))
        finally:
            os.unlink(tmp_csr_path)

    @app.route('/crl/<ca>.crl')
    def get_crl_by_path(ca):
        if ca not in ('root', 'intermediate'):
            abort(400)
        crl_dir = Path(app.config.get('PKI_DIR', pki_dir)) / 'crl'
        crl_file = crl_dir / f'{ca}.crl.pem'
        if not crl_file.exists():
            abort(404)
        return Response(crl_file.read_bytes(), mimetype='application/pkix-crl')

    @app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    return app