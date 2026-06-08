import pytest
import tempfile
import time
from pathlib import Path
from micropki import ca, database
'''
@pytest.mark.perf
def test_issue_1000_certs():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)
        start = time.time()
        for i in range(1000):
            ca.issue_certificate(
                ca_cert_path=str(pki_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(pki_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='server',
                subject=f'CN=cert{i}',
                san_list=[f'dns:cert{i}.local'],
                out_dir=str(pki_dir/'certs'),
                validity_days=30,
                pki_dir=str(pki_dir),
                force=True
            )
        elapsed = time.time() - start
        print(f"Issued 1000 certificates in {elapsed:.2f} seconds")
        assert elapsed < 60, f"Performance too slow: {elapsed:.2f}s"'''