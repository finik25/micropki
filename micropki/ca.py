import os
import stat
import datetime
from pathlib import Path

from . import crypto_utils
from . import certificates
from .logger import setup_logging
from cryptography.hazmat.primitives.serialization import Encoding

def init_ca(subject, key_type, key_size, passphrase_file, out_dir, validity_days,
            log_file=None, force=False):
    logger = setup_logging(log_file)

    # Validate key size consistency
    if key_type == 'rsa' and key_size != 4096:
        raise ValueError(f"RSA key size must be 4096, got {key_size}")
    if key_type == 'ecc' and key_size != 384:
        raise ValueError(f"ECC key size must be 384, got {key_size}")

    # Read passphrase
    try:
        with open(passphrase_file, 'rb') as f:
            passphrase = f.read().strip()
    except Exception as e:
        logger.error(f"Failed to read passphrase file: {e}")
        raise

    # Create directories
    out_path = Path(out_dir)
    private_dir = out_path / 'private'
    certs_dir = out_path / 'certs'
    try:
        out_path.mkdir(exist_ok=True, parents=True)
        private_dir.mkdir(exist_ok=True, parents=True)
        certs_dir.mkdir(exist_ok=True, parents=True)
        # Set permissions on Unix
        if os.name == 'posix':
            private_dir.chmod(0o700)
    except Exception as e:
        logger.error(f"Failed to create directories: {e}")
        raise

    # Check if output files already exist
    key_path = private_dir / 'ca.key.pem'
    cert_path = certs_dir / 'ca.cert.pem'
    policy_path = out_path / 'policy.txt'
    if (key_path.exists() or cert_path.exists() or policy_path.exists()) and not force:
        raise FileExistsError("Output files already exist. Use --force to overwrite.")

    # Generate key
    logger.info("Generating private key...")
    if key_type == 'rsa':
        private_key = crypto_utils.generate_rsa_key()
    else:
        private_key = crypto_utils.generate_ecc_key()
    logger.info("Key generation completed.")

    # Create self-signed certificate
    logger.info("Creating self-signed certificate...")
    certificate = certificates.create_self_signed_cert(
        subject, private_key, validity_days, key_type
    )
    logger.info("Certificate created.")

    # Encrypt and save private key
    key_pem = crypto_utils.encrypt_private_key(private_key, passphrase)
    with open(key_path, 'wb') as f:
        f.write(key_pem)
    if os.name == 'posix':
        os.chmod(key_path, 0o600)
    logger.info(f"Private key saved to {key_path}")

    # Save certificate
    with open(cert_path, 'wb') as f:
        f.write(certificate.public_bytes(Encoding.PEM))
    logger.info(f"Certificate saved to {cert_path}")

    # Generate policy.txt (исправленная версия)
    with open(policy_path, 'w') as f:
        f.write("Certificate Policy Document for MicroPKI Root CA\n")
        f.write(f"CA Name: {subject}\n")
        f.write(f"Certificate Serial Number: {hex(certificate.serial_number)}\n")
        f.write(f"Validity Period: {certificate.not_valid_before_utc} to {certificate.not_valid_after_utc}\n")
        f.write(f"Key Algorithm: {key_type.upper()} {key_size}\n")
        f.write("Purpose: Root CA for MicroPKI demonstration.\n")
        f.write("Policy Version: 1.0\n")
        f.write(f"Creation Date: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
    logger.info(f"Policy document saved to {policy_path}")

    return key_path, cert_path, policy_path