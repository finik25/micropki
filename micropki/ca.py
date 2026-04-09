import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from . import crypto_utils
from . import certificates
from .logger import setup_logging
from . import database


def init_ca(subject, key_type, key_size, passphrase_file, out_dir, validity_days,
            log_file=None, force=False, log_format='text'):
    logger = setup_logging(log_file, log_format=log_format)

    if key_type == 'rsa' and key_size != 4096:
        raise ValueError(f"RSA key size must be 4096, got {key_size}")
    if key_type == 'ecc' and key_size != 384:
        raise ValueError(f"ECC key size must be 384, got {key_size}")

    with open(passphrase_file, 'rb') as f:
        passphrase = f.read().strip()

    out_path = Path(out_dir)
    private_dir = out_path / 'private'
    certs_dir = out_path / 'certs'
    out_path.mkdir(exist_ok=True, parents=True)
    private_dir.mkdir(exist_ok=True, parents=True)
    certs_dir.mkdir(exist_ok=True, parents=True)
    if os.name == 'posix':
        private_dir.chmod(0o700)

    key_path = private_dir / 'ca.key.pem'
    cert_path = certs_dir / 'ca.cert.pem'
    policy_path = out_path / 'policy.txt'
    if (key_path.exists() or cert_path.exists() or policy_path.exists()) and not force:
        raise FileExistsError("Output files already exist. Use --force to overwrite.")

    logger.info("Generating private key...")
    if key_type == 'rsa':
        private_key = crypto_utils.generate_rsa_key()
    else:
        private_key = crypto_utils.generate_ecc_key()
    logger.info("Key generation completed.")

    logger.info("Creating self-signed certificate...")
    certificate = certificates.create_self_signed_cert(subject, private_key, validity_days, key_type)
    logger.info("Certificate created.")

    key_pem = crypto_utils.encrypt_private_key(private_key, passphrase)
    with open(key_path, 'wb') as f:
        f.write(key_pem)
    if os.name == 'posix':
        os.chmod(key_path, 0o600)
    logger.info(f"Private key saved to {key_path}")

    with open(cert_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Certificate saved to {cert_path}")

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


def create_intermediate_ca(root_cert_path, root_key_path, root_pass_file, subject, key_type, key_size,
                           passphrase_file, out_dir, validity_days, pathlen, log_file=None, force=False,
                           pki_dir=None, log_format='text'):
    logger = setup_logging(log_file, log_format=log_format)

    # Load root CA
    with open(root_cert_path, 'rb') as f:
        root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(root_key_path, 'rb') as f:
        root_key_data = f.read()
    with open(root_pass_file, 'rb') as f:
        root_pass = f.read().strip()
    root_private_key = serialization.load_pem_private_key(root_key_data, root_pass, default_backend())

    # Read passphrase for intermediate key
    with open(passphrase_file, 'rb') as f:
        intermediate_pass = f.read().strip()

    # Generate intermediate key
    logger.info("Generating intermediate CA private key...")
    if key_type == 'rsa':
        private_key = crypto_utils.generate_rsa_key()
    else:
        private_key = crypto_utils.generate_ecc_key()
    logger.info("Key generation completed.")

    # Determine paths
    out_path = Path(out_dir)
    private_dir = out_path / 'private'
    certs_dir = out_path / 'certs'
    key_path = private_dir / 'intermediate.key.pem'
    cert_path = certs_dir / 'intermediate.cert.pem'

    # Check for existing files BEFORE any DB operation
    if not force:
        if key_path.exists():
            raise FileExistsError(f"Intermediate key already exists: {key_path}. Use --force to overwrite.")
        if cert_path.exists():
            raise FileExistsError(f"Intermediate certificate already exists: {cert_path}. Use --force to overwrite.")

    # Determine database path
    if pki_dir is None:
        pki_dir = out_dir
    db_path = Path(pki_dir) / 'micropki.db'

    # Generate unique serial number if database exists
    serial_number = None
    if database.db_exists(str(db_path)):
        try:
            serial_number = database.generate_unique_serial(str(db_path))
            logger.info(f"Generated unique serial for intermediate CA: {hex(serial_number)}")
        except Exception as e:
            logger.warning(f"Could not generate unique serial from DB: {e}, using random serial")
    else:
        logger.warning("Database not found, intermediate certificate serial will be random (not guaranteed unique)")

    # Create intermediate certificate
    logger.info("Signing intermediate CSR with Root CA...")
    intermediate_cert = certificates.create_intermediate_certificate(
        subject, private_key.public_key(), root_cert, root_private_key, validity_days, pathlen,
        serial_number=serial_number
    )
    logger.info("Intermediate certificate created.")

    cert_serial_hex = hex(intermediate_cert.serial_number)
    db_inserted = False

    # Insert into database if exists
    if database.db_exists(str(db_path)):
        try:
            database.insert_certificate(str(db_path), intermediate_cert, root_cert.subject)
            db_inserted = True
            logger.info(f"Inserted intermediate certificate into database (serial={cert_serial_hex})")
        except Exception as e:
            logger.error(f"Failed to insert intermediate certificate into database: {e}")
            raise  # abort operation

    # Save encrypted key and certificate
    private_dir.mkdir(exist_ok=True, parents=True)
    certs_dir.mkdir(exist_ok=True, parents=True)

    try:
        with open(key_path, 'wb') as f:
            f.write(crypto_utils.encrypt_private_key(private_key, intermediate_pass))
        if os.name == 'posix':
            os.chmod(key_path, 0o600)
        logger.info(f"Intermediate private key saved to {key_path}")

        with open(cert_path, 'wb') as f:
            f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Intermediate certificate saved to {cert_path}")
    except Exception as e:
        if db_inserted:
            database.update_cert_status(str(db_path), cert_serial_hex, 'revoked', reason='issuance_failed')
            logger.error(f"File write failed, database entry marked as revoked: {e}")
        raise

    # Update policy.txt
    policy_path = out_path / 'policy.txt'
    with open(policy_path, 'a') as f:
        f.write("\n--- Intermediate CA ---\n")
        f.write(f"Subject: {subject}\n")
        f.write(f"Serial Number: {cert_serial_hex}\n")
        f.write(f"Validity: {intermediate_cert.not_valid_before_utc} to {intermediate_cert.not_valid_after_utc}\n")
        f.write(f"Key Algorithm: {key_type.upper()} {key_size}\n")
        f.write(f"Path Length: {pathlen}\n")
        f.write(f"Issuer: {root_cert.subject}\n")
    logger.info(f"Policy document updated at {policy_path}")

    return key_path, cert_path


def issue_certificate(ca_cert_path, ca_key_path, ca_pass_file, template, subject, san_list,
                      out_dir, validity_days, csr_path=None, log_file=None, pki_dir=None,
                      log_format='text', force=False):
    logger = setup_logging(log_file, log_format=log_format)

    # Load CA
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_key_path, 'rb') as f:
        ca_key_data = f.read()
    with open(ca_pass_file, 'rb') as f:
        ca_pass = f.read().strip()
    ca_private_key = serialization.load_pem_private_key(ca_key_data, ca_pass, default_backend())

    # Determine pki_dir and db_path
    if pki_dir is None:
        pki_dir = Path(out_dir).parent
    db_path = Path(pki_dir) / 'micropki.db'
    db_available = database.db_exists(str(db_path))

    out_path = Path(out_dir)
    out_path.mkdir(exist_ok=True, parents=True)

    # Determine output paths and subject early (for file existence check)
    from cryptography.x509.oid import NameOID
    effective_subject = None
    cn = None
    if csr_path:
        # Load CSR to get subject
        with open(csr_path, 'rb') as f:
            csr_data = f.read()
        csr = x509.load_pem_x509_csr(csr_data, default_backend())
        effective_subject = csr.subject
        for attr in effective_subject:
            if attr.oid == NameOID.COMMON_NAME:
                cn = attr.value
                break
        if not cn:
            cn = "external"
        cert_filename = f"{cn.replace(' ', '_').replace('*', 'wildcard')}.cert.pem"
        cert_path = out_path / cert_filename
        key_path = None
    else:
        if not subject:
            raise ValueError("Subject is required when CSR is not provided")
        effective_subject = certificates.parse_dn(subject)
        for attr in effective_subject:
            if attr.oid == NameOID.COMMON_NAME:
                cn = attr.value
                break
        if not cn:
            cn = "cert"
        safe_cn = cn.replace(' ', '_').replace('*', 'wildcard')
        cert_filename = f"{safe_cn}.cert.pem"
        key_filename = f"{safe_cn}.key.pem"
        cert_path = out_path / cert_filename
        key_path = out_path / key_filename

    # Check for existing files before any DB or crypto operations
    if not force:
        if cert_path.exists():
            raise FileExistsError(f"Certificate file already exists: {cert_path}. Use --force to overwrite.")
        if key_path and key_path.exists():
            raise FileExistsError(f"Private key file already exists: {key_path}. Use --force to overwrite.")

    # Generate unique serial number if database exists
    serial_number = None
    if db_available:
        try:
            serial_number = database.generate_unique_serial(str(db_path))
            logger.info(f"Generated unique serial: {hex(serial_number)}")
        except Exception as e:
            logger.warning(f"Could not generate unique serial from DB: {e}, using random serial")
    else:
        logger.warning("Database not found, certificate serial will be random (not guaranteed unique)")

    if csr_path:
        # Use external CSR (already loaded above)
        cert = certificates.sign_csr(csr, ca_cert, ca_private_key, validity_days, template, san_list,
                                     serial_number=serial_number)
        cert_serial_hex = hex(cert.serial_number)

        db_inserted = False
        if db_available:
            try:
                database.insert_certificate(str(db_path), cert, ca_cert.subject)
                db_inserted = True
                logger.info(f"Inserted certificate into database (serial={cert_serial_hex})")
            except Exception as e:
                logger.error(f"Failed to insert certificate into database: {e}")
                raise

        try:
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            logger.info(f"Certificate saved to {cert_path}")
            logger.info("No private key saved (external CSR provided).")
        except Exception as e:
            if db_inserted:
                database.update_cert_status(str(db_path), cert_serial_hex, 'revoked', reason='issuance_failed')
            raise

        return cert_path, None

    else:
        # Generate new key pair
        logger.info(f"Generating {template} private key...")
        ee_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        logger.info("Key generation completed.")
        csr = certificates.create_csr(subject, ee_private_key, extensions=None)
        cert = certificates.sign_csr(csr, ca_cert, ca_private_key, validity_days, template, san_list,
                                     serial_number=serial_number)
        cert_serial_hex = hex(cert.serial_number)

        db_inserted = False
        if db_available:
            try:
                database.insert_certificate(str(db_path), cert, ca_cert.subject)
                db_inserted = True
                logger.info(f"Inserted certificate into database (serial={cert_serial_hex})")
            except Exception as e:
                logger.error(f"Failed to insert certificate into database: {e}")
                raise

        try:
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, 'wb') as f:
                f.write(ee_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            if os.name == 'posix':
                os.chmod(key_path, 0o600)
            logger.info(f"Certificate saved to {cert_path}")
            logger.info(f"Private key (unencrypted) saved to {key_path}")
            logger.warning("End-entity private key stored unencrypted. Ensure proper file permissions.")
            logger.info(f"Issued {template} certificate: serial={cert_serial_hex}, subject={subject}, SANs={san_list}")
        except Exception as e:
            if db_inserted:
                database.update_cert_status(str(db_path), cert_serial_hex, 'revoked', reason='issuance_failed')
            raise

        return cert_path, key_path


def verify_certificate(cert_path):
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    if cert.issuer != cert.subject:
        return False, "Not self-signed certificate (issuer != subject)"
    pub_key = cert.public_key()
    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            return False, f"Unsupported key type: {type(pub_key)}"
    except Exception as e:
        return False, f"Signature verification failed: {e}"
    return True, "Certificate is valid"


def verify_chain(leaf_path, root_path, intermediate_path=None):
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    import datetime

    def load_cert(path):
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    leaf = load_cert(leaf_path)
    root = load_cert(root_path)
    intermediate = load_cert(intermediate_path) if intermediate_path else None

    chain = [leaf]
    if intermediate:
        chain.append(intermediate)
    chain.append(root)

    for i in range(len(chain) - 1):
        subject_cert = chain[i]
        issuer_cert = chain[i+1]

        if subject_cert.issuer != issuer_cert.subject:
            return False, f"Chain break: {subject_cert.subject} issuer {subject_cert.issuer} does not match {issuer_cert.subject}"

        pub_key = issuer_cert.public_key()
        try:
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    subject_cert.signature_hash_algorithm
                )
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm)
                )
            else:
                return False, f"Unsupported key type: {type(pub_key)}"
        except Exception as e:
            return False, f"Signature verification failed: {e}"

        now = datetime.datetime.now(datetime.timezone.utc)
        if not (subject_cert.not_valid_before_utc <= now <= subject_cert.not_valid_after_utc):
            return False, f"Certificate {subject_cert.subject} is not valid at current time"

        if i < len(chain) - 2:
            try:
                bc = issuer_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
                if not bc.value.ca:
                    return False, f"Certificate {issuer_cert.subject} is not a CA (BasicConstraints CA=FALSE)"
            except x509.ExtensionNotFound:
                return False, f"Certificate {issuer_cert.subject} missing BasicConstraints extension"

    return True, "Chain is valid"