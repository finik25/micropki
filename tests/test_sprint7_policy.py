import pytest
import tempfile
from pathlib import Path
from micropki import ca, database

def test_policy_validity_too_long():
    """Попытка выдать сертификат с превышением максимального срока действия."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        with pytest.raises(ValueError, match="exceeds maximum"):
            ca.issue_certificate(
                ca_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(pki_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='server',
                subject='CN=test',
                san_list=['dns:test.local'],
                out_dir=str(pki_dir/'certs'),
                validity_days=400,
                pki_dir=str(pki_dir),
                force=True
            )

def test_policy_weak_key_csr():
    """Попытка использовать CSR с RSA-1024."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization

    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        # Генерация слабого ключа
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")])
        ).sign(weak_key, hashes.SHA256())
        csr_path = pki_dir / 'weak.csr'
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(ValueError, match="RSA key size 1024 is below minimum"):
            ca.issue_certificate(
                ca_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(pki_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='server',
                subject=None,
                san_list=[],
                out_dir=str(pki_dir/'certs'),
                validity_days=30,
                csr_path=str(csr_path),
                pki_dir=str(pki_dir),
                force=True
            )

def test_policy_wildcard_san():
    """Попытка выдать server сертификат с wildcard SAN."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        with pytest.raises(ValueError, match="Wildcard DNS name"):
            ca.issue_certificate(
                ca_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(pki_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='server',
                subject='CN=wildcard',
                san_list=['dns:*.example.com'],
                out_dir=str(pki_dir/'certs'),
                validity_days=30,
                pki_dir=str(pki_dir),
                force=True
            )

def test_policy_disallowed_san_type():
    """Попытка выдать server сертификат с email SAN."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        with pytest.raises(ValueError, match="SAN type 'email' is not allowed"):
            ca.issue_certificate(
                ca_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(pki_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='server',
                subject='CN=test',
                san_list=['email:admin@example.com'],
                out_dir=str(pki_dir/'certs'),
                validity_days=30,
                pki_dir=str(pki_dir),
                force=True
            )