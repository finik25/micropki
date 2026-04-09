import pytest
import tempfile
import json
from pathlib import Path
from micropki import database, ca, repository
from flask import Flask
from datetime import datetime, timezone, timedelta

def test_db_init():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        database.init_db(str(db_path))
        assert database.db_exists(str(db_path))

def test_insert_and_retrieve():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        database.init_db(str(db_path))
        # Create a minimal self-signed cert for testing
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        import datetime
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private_key.public_key()).serial_number(12345).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).sign(private_key, hashes.SHA256())
        database.insert_certificate(str(db_path), cert, subject)
        retrieved = database.get_cert_by_serial(str(db_path), hex(12345))
        assert retrieved is not None
        assert retrieved['subject'] == subject.rfc4514_string()

def test_list_certs():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        database.init_db(str(db_path))
        certs = database.list_certs(str(db_path))
        assert isinstance(certs, list)

def test_get_revoked_certs():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        database.init_db(str(db_path))
        revoked = database.get_revoked_certs(str(db_path))
        assert isinstance(revoked, list)

def test_http_endpoints():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir)
        certs_dir = pki_dir / 'certs'
        certs_dir.mkdir()
        db_path = pki_dir / 'micropki.db'
        database.init_db(str(db_path))
        # Create dummy CA certs
        (certs_dir / 'ca.cert.pem').write_text("-----BEGIN CERTIFICATE-----\nDUMMY\n-----END CERTIFICATE-----")
        (certs_dir / 'intermediate.cert.pem').write_text("-----BEGIN CERTIFICATE-----\nDUMMY INT\n-----END CERTIFICATE-----")
        app = repository.create_app(str(pki_dir))
        client = app.test_client()
        # Test /ca/root
        resp = client.get('/ca/root')
        assert resp.status_code == 200
        assert b'DUMMY' in resp.data
        # Test /ca/intermediate
        resp = client.get('/ca/intermediate')
        assert resp.status_code == 200
        # Test /crl
        resp = client.get('/crl')
        assert resp.status_code == 501
        # Test /certificate with invalid serial
        resp = client.get('/certificate/nothex')
        assert resp.status_code == 400


def test_generate_unique_serial():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        database.init_db(str(db_path))
        serial1 = database.generate_unique_serial(str(db_path))
        serial2 = database.generate_unique_serial(str(db_path))
        assert serial1 != serial2

        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])

        # Первый сертификат с serial1 – вставляем успешно
        cert1 = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(subject) \
            .public_key(private_key.public_key()) \
            .serial_number(serial1) \
            .not_valid_before(datetime.now(timezone.utc)) \
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)) \
            .sign(private_key, hashes.SHA256())
        database.insert_certificate(str(db_path), cert1, subject)

        # Второй сертификат с тем же serial1 – должен вызвать ошибку дубликата
        cert2 = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(subject) \
            .public_key(private_key.public_key()) \
            .serial_number(serial1) \
            .not_valid_before(datetime.now(timezone.utc)) \
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)) \
            .sign(private_key, hashes.SHA256())
        with pytest.raises(ValueError, match="Duplicate serial"):
            database.insert_certificate(str(db_path), cert2, subject)

def test_stress_100_certificates():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test.db'
        database.init_db(str(db_path))
        # Создаём корневой CA для подписи
        from micropki.crypto_utils import generate_rsa_key
        from micropki.certificates import create_self_signed_cert
        root_key = generate_rsa_key()
        root_cert = create_self_signed_cert("CN=Stress Root", root_key, 3650, "rsa")
        # Генерируем 100 сертификатов
        serials = set()
        for i in range(100):
            serial = database.generate_unique_serial(str(db_path))
            assert serial not in serials
            serials.add(serial)
            # Создаём простой сертификат
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import NameOID
            ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"cert{i}")])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(root_cert.subject).public_key(ee_key.public_key()).serial_number(serial).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(root_key, hashes.SHA256())
            database.insert_certificate(str(db_path), cert, root_cert.subject)
        # Проверяем, что все 100 записей в БД
        certs = database.list_certs(str(db_path), limit=200)
        assert len(certs) == 100