import os
import tempfile
import pytest
from pathlib import Path
from micropki.ca import init_ca

def test_init_ca_rsa():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir) / "pki"
        pass_file = Path(tmpdir) / "pass.txt"
        with open(pass_file, "w") as f:
            f.write("testpass\n")
        # Run init
        key_path, cert_path, policy_path = init_ca(
            subject="CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(pass_file),
            out_dir=str(out_dir),
            validity_days=365,
            force=True
        )
        assert key_path.exists()
        assert cert_path.exists()
        assert policy_path.exists()
        # Check key file permissions (Unix only)
        if os.name == 'posix':
            mode = os.stat(key_path).st_mode
            assert mode & 0o777 == 0o600

def test_init_ca_ecc():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir) / "pki"
        pass_file = Path(tmpdir) / "pass.txt"
        with open(pass_file, "w") as f:
            f.write("testpass\n")
        init_ca(
            subject="CN=Test ECC CA",
            key_type="ecc",
            key_size=384,
            passphrase_file=str(pass_file),
            out_dir=str(out_dir),
            validity_days=365,
            force=True
        )
        assert (out_dir / "private" / "ca.key.pem").exists()
        assert (out_dir / "certs" / "ca.cert.pem").exists()

def test_init_ca_overwrite_no_force():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir) / "pki"
        pass_file = Path(tmpdir) / "pass.txt"
        with open(pass_file, "w") as f:
            f.write("testpass\n")
        # First init
        init_ca("CN=Root", "rsa", 4096, str(pass_file), str(out_dir), 365, force=True)
        # Second init without force should raise
        with pytest.raises(FileExistsError):
            init_ca("CN=Root2", "rsa", 4096, str(pass_file), str(out_dir), 365, force=False)