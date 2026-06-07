import pytest
import tempfile
import subprocess
import threading
import time
import socket
import requests
from pathlib import Path
from cryptography import x509
from micropki import ca, database, revocation
from micropki.ocsp_responder import create_ocsp_app
from asn1crypto import algos, ocsp

def wait_for_server(url, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200 or r.status_code == 405:
                return True
        except:
            time.sleep(0.5)
    return False

@pytest.fixture(scope="module")
def ocsp_environment():
    tmpdir = tempfile.TemporaryDirectory()
    pki_dir = Path(tmpdir.name) / 'pki'
    pki_dir.mkdir()
    db_path = pki_dir / 'micropki.db'
    database.migrate(str(db_path))

    pass_file = pki_dir / 'pass.txt'
    pass_file.write_text('rootpass')
    ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

    int_pass = pki_dir / 'int_pass.txt'
    int_pass.write_text('intsecret')
    ca.create_intermediate_ca(
        root_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
        root_key_path=str(pki_dir/'private'/'ca.key.pem'),
        root_pass_file=str(pass_file),
        subject='CN=Intermediate',
        key_type='rsa', key_size=4096,
        passphrase_file=str(int_pass),
        out_dir=str(pki_dir),
        validity_days=365, pathlen=0, force=True,
        pki_dir=str(pki_dir)
    )

    good_cert_path, _ = ca.issue_certificate(
        ca_cert_path=str(pki_dir/'certs'/'intermediate.cert.pem'),
        ca_key_path=str(pki_dir/'private'/'intermediate.key.pem'),
        ca_pass_file=str(int_pass),
        template='server',
        subject='CN=good.local',
        san_list=['dns:good.local'],
        out_dir=str(pki_dir/'certs'),
        validity_days=30,
        pki_dir=str(pki_dir),
        force=True
    )

    ocsp_cert_path, ocsp_key_path = ca.issue_certificate(
        ca_cert_path=str(pki_dir/'certs'/'intermediate.cert.pem'),
        ca_key_path=str(pki_dir/'private'/'intermediate.key.pem'),
        ca_pass_file=str(int_pass),
        template='ocsp_signer',
        subject='CN=OCSP Responder',
        san_list=['dns:localhost'],
        out_dir=str(pki_dir/'certs'),
        validity_days=365,
        pki_dir=str(pki_dir),
        force=True
    )

    app = create_ocsp_app(
        db_path=str(db_path),
        responder_cert_path=str(ocsp_cert_path),
        responder_key_path=str(ocsp_key_path),
        ca_cert_path=str(pki_dir / 'certs' / 'intermediate.cert.pem'),
        cache_ttl=60,
        log_file=None,
        log_format='text'
    )
    assert app is not None, "OCSP app creation failed"

    def run_server():
        app.run(host='127.0.0.1', port=8888, debug=False, threaded=True)

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    assert wait_for_server('http://127.0.0.1:8888/ocsp'), "OCSP server did not start"

    yield {
        'pki_dir': pki_dir,
        'int_cert': pki_dir / 'certs' / 'intermediate.cert.pem',
        'root_cert': pki_dir / 'certs' / 'ca.cert.pem',
        'good_cert': good_cert_path,
        'ocsp_url': 'http://127.0.0.1:8888/ocsp',
        'db_path': db_path,
        'int_pass': int_pass,
    }

    tmpdir.cleanup()

@pytest.mark.slow
def test_ocsp_good(ocsp_environment):
    env = ocsp_environment
    cmd = [
        'openssl', 'ocsp',
        '-issuer', str(env['int_cert']),
        '-cert', str(env['good_cert']),
        '-url', env['ocsp_url'],
        '-CAfile', str(env['root_cert']),
        '-resp_text', '-no_nonce'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Проверяем, что подпись верифицирована и статус good
    assert 'Response verify OK' in result.stderr, "Signature verification failed"
    assert 'Cert Status: good' in result.stdout, "Certificate status is not 'good'"

@pytest.mark.slow
def test_ocsp_revoked(ocsp_environment):
    env = ocsp_environment
    revoked_cert_path, _ = ca.issue_certificate(
        ca_cert_path=str(env['pki_dir']/'certs'/'intermediate.cert.pem'),
        ca_key_path=str(env['pki_dir']/'private'/'intermediate.key.pem'),
        ca_pass_file=str(env['int_pass']),
        template='server',
        subject='CN=revoked.local',
        san_list=['dns:revoked.local'],
        out_dir=str(env['pki_dir']/'certs'),
        validity_days=30,
        pki_dir=str(env['pki_dir']),
        force=True
    )
    with open(revoked_cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    serial_hex = hex(cert.serial_number)
    revocation.revoke_certificate(str(env['db_path']), serial_hex, reason='keyCompromise')

    cmd = [
        'openssl', 'ocsp',
        '-issuer', str(env['int_cert']),
        '-cert', str(revoked_cert_path),
        '-url', env['ocsp_url'],
        '-CAfile', str(env['root_cert']),
        '-resp_text', '-no_nonce'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert 'Response verify OK' in result.stderr, "Signature verification failed"
    assert 'Cert Status: revoked' in result.stdout, "Certificate status is not 'revoked'"

@pytest.mark.slow
def test_ocsp_unknown(ocsp_environment):
    env = ocsp_environment
    fake_serial = '0xdeadbeef'
    cmd = [
        'openssl', 'ocsp',
        '-issuer', str(env['int_cert']),
        '-serial', fake_serial,
        '-url', env['ocsp_url'],
        '-CAfile', str(env['root_cert']),
        '-resp_text', '-no_nonce'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Для неизвестного сертификата OpenSSL должен вернуть ошибку (ответ не найден)
    # Проверяем, что в ответе нет статуса good/revoked
    assert 'Cert Status: good' not in result.stdout
    assert 'Cert Status: revoked' not in result.stdout

@pytest.mark.slow
def test_ocsp_nonce(ocsp_environment):
    env = ocsp_environment
    cmd = [
        'openssl', 'ocsp',
        '-issuer', str(env['int_cert']),
        '-cert', str(env['good_cert']),
        '-url', env['ocsp_url'],
        '-CAfile', str(env['root_cert']),
        '-resp_text', '-nonce'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert 'Response verify OK' in result.stderr, "Signature verification failed"
    assert 'OCSP Nonce' in result.stdout or 'Nonce' in result.stdout, "Nonce not echoed"

def test_ocsp_signer_cert_extensions():
    """Проверка расширений OCSP-сертификата."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)
        int_pass = pki_dir / 'int_pass.txt'
        int_pass.write_text('intsecret')
        ca.create_intermediate_ca(
            root_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
            root_key_path=str(pki_dir/'private'/'ca.key.pem'),
            root_pass_file=str(pass_file),
            subject='CN=Intermediate',
            key_type='rsa', key_size=4096,
            passphrase_file=str(int_pass),
            out_dir=str(pki_dir),
            validity_days=365, pathlen=0, force=True,
            pki_dir=str(pki_dir)
        )
        ocsp_cert_path, _ = ca.issue_certificate(
            ca_cert_path=str(pki_dir/'certs'/'intermediate.cert.pem'),
            ca_key_path=str(pki_dir/'private'/'intermediate.key.pem'),
            ca_pass_file=str(int_pass),
            template='ocsp_signer',
            subject='CN=OCSP Test',
            san_list=[],
            out_dir=str(pki_dir/'certs'),
            validity_days=365,
            pki_dir=str(pki_dir),
            force=True
        )
        with open(ocsp_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is False
        ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        assert ku.value.digital_signature is True
        assert ku.value.key_cert_sign is False
        eku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        ocsp_oid = x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.3.9")
        assert ocsp_oid in eku.value

def test_issue_ocsp_cert():
    """Проверка CLI команды issue-ocsp-cert."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)
        int_pass = pki_dir / 'int_pass.txt'
        int_pass.write_text('intsecret')
        ca.create_intermediate_ca(
            root_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
            root_key_path=str(pki_dir/'private'/'ca.key.pem'),
            root_pass_file=str(pass_file),
            subject='CN=Intermediate',
            key_type='rsa', key_size=4096,
            passphrase_file=str(int_pass),
            out_dir=str(pki_dir),
            validity_days=365, pathlen=0, force=True,
            pki_dir=str(pki_dir)
        )
        from micropki.cli import main as cli_main
        import sys
        sys.argv = ['micropki', 'ca', 'issue-ocsp-cert',
                    '--ca-cert', str(pki_dir/'certs'/'intermediate.cert.pem'),
                    '--ca-key', str(pki_dir/'private'/'intermediate.key.pem'),
                    '--ca-pass-file', str(int_pass),
                    '--subject', 'CN=OCSP Responder',
                    '--key-type', 'rsa', '--key-size', '2048',
                    '--out-dir', str(pki_dir/'certs'),
                    '--force']
        cli_main()
        ocsp_cert_path = pki_dir / 'certs' / 'OCSP_Responder.cert.pem'
        assert ocsp_cert_path.exists()
        with open(ocsp_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is False
        ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        assert ku.value.digital_signature is True
        eku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        ocsp_oid = x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.3.9")
        assert ocsp_oid in eku.value

def test_cert_id_creation():
    hash_alg = algos.DigestAlgorithm({'algorithm': 'sha1'})
    cert_id = ocsp.CertId({
        'hash_algorithm': hash_alg,
        'issuer_name_hash': b'\x00'*20,
        'issuer_key_hash': b'\x00'*20,
        'serial_number': 12345,
    })
    assert cert_id is not None

def test_ocsp_responder_good(ocsp_environment):
    """Проверка OCSP для хорошего сертификата через фикстуру."""
    env = ocsp_environment
    cmd = [
        'openssl', 'ocsp',
        '-issuer', str(env['int_cert']),
        '-cert', str(env['good_cert']),
        '-url', env['ocsp_url'],
        '-CAfile', str(env['root_cert']),
        '-resp_text', '-no_nonce'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Проверяем, что подпись верифицирована (не проверяем код возврата OpenSSL)
    assert 'Response verify OK' in result.stderr, "Signature verification failed"
    # Статус good может быть как в stdout, так и в stderr
    assert 'Cert Status: good' in result.stdout or 'Cert Status: good' in result.stderr