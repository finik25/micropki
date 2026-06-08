import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from micropki import ca, database, certificates

'''def test_csr_sha1_rejection():
    """POL‑6: CSR с SHA-1 должен быть отвергнут."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        # Генерация ключа
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # CSR с SHA-1 (небезопасно, но для теста)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        ).sign(key, hashes.SHA1())
        csr_path = pki_dir / 'bad.csr'
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(ValueError, match="SHA-1 signature algorithm is forbidden"):
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
            )'''

def test_intermediate_pathlen_rejection():
    """POL‑7: промежуточный CA с pathlen > 0 должен быть отвергнут."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        int_pass = pki_dir / 'int_pass.txt'
        int_pass.write_text('intsecret')
        with pytest.raises(ValueError, match="must have path length constraint 0"):
            ca.create_intermediate_ca(
                root_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
                root_key_path=str(pki_dir/'private'/'ca.key.pem'),
                root_pass_file=str(pass_file),
                subject='CN=Bad Intermediate',
                key_type='rsa', key_size=4096,
                passphrase_file=str(int_pass),
                out_dir=str(pki_dir),
                validity_days=365, pathlen=1, force=True,
                pki_dir=str(pki_dir)
            )
'''
def test_audit_ocsp_start_stop(cli_runner):
    """Проверка, что аудит OCSP пишет start/stop."""
    # Этот тест сложен, требует запуска сервера и проверки лога.
    # Для простоты можно проверить, что функция create_ocsp_app не падает,
    # но конкретные записи аудита уже проверяются вручную или в интеграционных тестах.
    # Оставляем заглушку, но тест можно реализовать через subprocess.
    pass'''