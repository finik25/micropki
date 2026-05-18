import os
from pathlib import Path
from flask import Flask, abort, request, Response
import logging
import json
from datetime import datetime
from . import database
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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


def create_app(pki_dir, log_file=None, log_format='text'):
    app = Flask(__name__)
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
        return Response("CRL generation not yet implemented", status=501, mimetype='text/plain')

    @app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    return app