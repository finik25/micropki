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
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private_key.public_key()).serial_number(12345).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(private_key, hashes.SHA256())
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
        (certs_dir / 'ca.cert.pem').write_text("-----BEGIN CERTIFICATE-----\nDUMMY\n-----END CERTIFICATE-----")
        (certs_dir / 'intermediate.cert.pem').write_text("-----BEGIN CERTIFICATE-----\nDUMMY INT\n-----END CERTIFICATE-----")
        app = repository.create_app(str(pki_dir))
        client = app.test_client()
        resp = client.get('/ca/root')
        assert resp.status_code == 200
        assert b'DUMMY' in resp.data
        resp = client.get('/ca/intermediate')
        assert resp.status_code == 200
        resp = client.get('/crl')
        assert resp.status_code == 501
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

        cert1 = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(subject) \
            .public_key(private_key.public_key()) \
            .serial_number(serial1) \
            .not_valid_before(datetime.now(timezone.utc)) \
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)) \
            .sign(private_key, hashes.SHA256())
        database.insert_certificate(str(db_path), cert1, subject)

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
        from micropki.crypto_utils import generate_rsa_key
        from micropki.certificates import create_self_signed_cert
        root_key = generate_rsa_key()
        root_cert = create_self_signed_cert("CN=Stress Root", root_key, 3650, "rsa")
        serials = set()
        for i in range(100):
            serial = database.generate_unique_serial(str(db_path))
            assert serial not in serials
            serials.add(serial)
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import NameOID
            ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"cert{i}")])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(root_cert.subject).public_key(ee_key.public_key()).serial_number(serial).not_valid_before(datetime.now(timezone.utc)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(root_key, hashes.SHA256())
            database.insert_certificate(str(db_path), cert, root_cert.subject)
        certs = database.list_certs(str(db_path), limit=200)
        assert len(certs) == 100


# ========== TEST-15: Repository API Test – Certificate Fetch ==========
def test_repository_certificate_fetch():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir(parents=True, exist_ok=True)          # <-- ИСПРАВЛЕНО
        # Initialize DB and root CA
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)
        # Issue an end-entity certificate
        cert_path, _ = ca.issue_certificate(
            ca_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
            ca_key_path=str(pki_dir/'private'/'ca.key.pem'),
            ca_pass_file=str(pass_file),
            template='server',
            subject='CN=apitest.local',
            san_list=['dns:apitest.local'],
            out_dir=str(pki_dir/'certs'),
            validity_days=30,
            pki_dir=str(pki_dir)
        )
        # Start repository test client
        app = repository.create_app(str(pki_dir))
        client = app.test_client()
        # Extract serial from certificate
        from cryptography import x509
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        serial_hex = hex(cert.serial_number)
        # Request via API
        resp = client.get(f'/certificate/{serial_hex}')
        assert resp.status_code == 200
        assert resp.data == cert_path.read_bytes()


# ========== TEST-20: Integration Test (full workflow) ==========
def test_full_integration_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir(parents=True, exist_ok=True)          # <-- ИСПРАВЛЕНО
        # 1. Initialize DB
        db_path = pki_dir / 'micropki.db'
        database.migrate(str(db_path))
        # 2. Create Root CA
        root_pass = pki_dir / 'root_pass.txt'
        root_pass.write_text('rootsecret')
        ca.init_ca('CN=Root CA', 'rsa', 4096, str(root_pass), str(pki_dir), 365, force=True)
        # 3. Create Intermediate CA (auto-inserted)
        int_pass = pki_dir / 'int_pass.txt'
        int_pass.write_text('intsecret')
        ca.create_intermediate_ca(
            root_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
            root_key_path=str(pki_dir/'private'/'ca.key.pem'),
            root_pass_file=str(root_pass),
            subject='CN=Intermediate CA',
            key_type='rsa', key_size=4096,
            passphrase_file=str(int_pass),
            out_dir=str(pki_dir),
            validity_days=365, pathlen=0, force=True,
            pki_dir=str(pki_dir)
        )
        # 4. Issue 3 leaf certificates
        cert_paths = []
        for i in range(3):
            cp, _ = ca.issue_certificate(
                ca_cert_path=str(pki_dir/'certs'/'intermediate.cert.pem'),
                ca_key_path=str(pki_dir/'private'/'intermediate.key.pem'),
                ca_pass_file=str(int_pass),
                template='client',
                subject=f'CN=client{i}',
                san_list=[f'email:client{i}@example.com'],
                out_dir=str(pki_dir/'certs'),
                validity_days=30,
                pki_dir=str(pki_dir)
            )
            cert_paths.append(cp)
        # 5. Start repository (test client)
        app = repository.create_app(str(pki_dir))
        client = app.test_client()
        # 6. Fetch one leaf certificate via API and verify match
        from cryptography import x509
        with open(cert_paths[0], 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        serial_hex = hex(cert.serial_number)
        resp = client.get(f'/certificate/{serial_hex}')
        assert resp.status_code == 200
        assert resp.data == cert_paths[0].read_bytes()