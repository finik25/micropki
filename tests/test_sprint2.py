import pytest
import tempfile
from pathlib import Path
from micropki import ca, certificates
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def test_parse_san():
    san_list = certificates.parse_san(['dns:example.com', 'ip:192.168.1.1', 'email:admin@example.com'])
    assert len(san_list) == 3

def test_create_intermediate_ca():
    with tempfile.TemporaryDirectory() as tmpdir:
        # First create root CA
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        # Then create intermediate
        int_pass = Path(tmpdir) / 'int_pass.txt'
        int_pass.write_text('intsecret')
        ca.create_intermediate_ca(
            root_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
            root_key_path=str(root_dir/'private'/'ca.key.pem'),
            root_pass_file=str(pass_file),
            subject='CN=Intermediate',
            key_type='rsa',
            key_size=4096,
            passphrase_file=str(int_pass),
            out_dir=str(root_dir),
            validity_days=365,
            pathlen=0,
            force=True
        )
        assert (root_dir/'certs'/'intermediate.cert.pem').exists()
        assert (root_dir/'private'/'intermediate.key.pem').exists()

def test_issue_cert():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create root and intermediate (simplified: use root as CA for test)
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        # Issue a server certificate directly from root (for test)
        ca.issue_certificate(
            ca_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
            ca_key_path=str(root_dir/'private'/'ca.key.pem'),
            ca_pass_file=str(pass_file),
            template='server',
            subject='CN=testserver',
            san_list=['dns:test.local'],
            out_dir=str(root_dir/'certs'),
            validity_days=30
        )
        certs_dir = root_dir/'certs'
        assert any(f.name.endswith('.cert.pem') for f in certs_dir.iterdir())

def test_server_cert_missing_san():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        with pytest.raises(ValueError, match="Server certificate must have at least one DNS or IP SAN"):
            ca.issue_certificate(
                ca_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(root_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='server',
                subject='CN=test',
                san_list=[],
                out_dir=str(root_dir/'certs'),
                validity_days=30
            )

def test_code_signing_with_email_san():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        with pytest.raises(ValueError, match="only allows DNS or URI SANs"):
            ca.issue_certificate(
                ca_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(root_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(pass_file),
                template='code_signing',
                subject='CN=signer',
                san_list=['email:bad@example.com'],
                out_dir=str(root_dir/'certs'),
                validity_days=30
            )

def test_wrong_ca_passphrase():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        wrong_pass = Path(tmpdir) / 'wrong.txt'
        wrong_pass.write_text('wrong')
        with pytest.raises(Exception):  # cryptography will raise on load
            ca.issue_certificate(
                ca_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
                ca_key_path=str(root_dir/'private'/'ca.key.pem'),
                ca_pass_file=str(wrong_pass),
                template='client',
                subject='CN=client',
                san_list=[],
                out_dir=str(root_dir/'certs'),
                validity_days=30
            )

def test_verify_chain():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        # Create intermediate
        int_pass = Path(tmpdir) / 'int_pass.txt'
        int_pass.write_text('intsecret')
        ca.create_intermediate_ca(
            root_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
            root_key_path=str(root_dir/'private'/'ca.key.pem'),
            root_pass_file=str(pass_file),
            subject='CN=Intermediate',
            key_type='rsa', key_size=4096,
            passphrase_file=str(int_pass),
            out_dir=str(root_dir),
            validity_days=365, pathlen=0, force=True
        )
        # Issue leaf
        ca.issue_certificate(
            ca_cert_path=str(root_dir/'certs'/'intermediate.cert.pem'),
            ca_key_path=str(root_dir/'private'/'intermediate.key.pem'),
            ca_pass_file=str(int_pass),
            template='server',
            subject='CN=leaf',
            san_list=['dns:leaf.local'],
            out_dir=str(root_dir/'certs'),
            validity_days=30
        )
        # Find leaf certificate file
        leaf_file = next((root_dir/'certs').glob('leaf*.cert.pem'))
        # Verify chain
        valid, msg = ca.verify_chain(
            str(leaf_file),
            str(root_dir/'certs'/'ca.cert.pem'),
            str(root_dir/'certs'/'intermediate.cert.pem')
        )
        assert valid, msg

def test_issue_cert_with_external_csr():
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir) / 'root'
        pass_file = Path(tmpdir) / 'pass.txt'
        pass_file.write_text('secret')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(root_dir), 365, force=True)
        # Generate a key pair and CSR externally
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "external")])
        ).sign(private_key, hashes.SHA256())
        csr_path = Path(tmpdir) / 'request.csr'
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        # Issue certificate using CSR
        cert_path, key_path = ca.issue_certificate(
            ca_cert_path=str(root_dir/'certs'/'ca.cert.pem'),
            ca_key_path=str(root_dir/'private'/'ca.key.pem'),
            ca_pass_file=str(pass_file),
            template='client',
            subject='ignored',
            san_list=[],
            out_dir=str(root_dir/'certs'),
            validity_days=30,
            csr_path=str(csr_path)
        )
        assert cert_path.exists()
        assert key_path is None  # no private key saved