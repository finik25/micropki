import argparse
import sys
import os
import json
import csv
from pathlib import Path
from . import ca
from . import database
from .config import load_config


def main():
    parser = argparse.ArgumentParser(description='MicroPKI - Minimal PKI Tool')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # ---------- ca ----------
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', required=True)

    # ca init
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument('--subject', required=True)
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    init_parser.add_argument('--key-size', type=int, default=4096)
    init_parser.add_argument('--passphrase-file', required=True)
    init_parser.add_argument('--out-dir', default='./pki')
    init_parser.add_argument('--validity-days', type=int, default=3650)
    init_parser.add_argument('--log-file')
    init_parser.add_argument('--log-format', choices=['text', 'json'], default='text')
    init_parser.add_argument('--force', action='store_true')

    # ca issue-intermediate
    int_parser = ca_subparsers.add_parser('issue-intermediate', help='Create an Intermediate CA')
    int_parser.add_argument('--root-cert', required=True)
    int_parser.add_argument('--root-key', required=True)
    int_parser.add_argument('--root-pass-file', required=True)
    int_parser.add_argument('--subject', required=True)
    int_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    int_parser.add_argument('--key-size', type=int, default=4096)
    int_parser.add_argument('--passphrase-file', required=True)
    int_parser.add_argument('--out-dir', default='./pki')
    int_parser.add_argument('--validity-days', type=int, default=1825)
    int_parser.add_argument('--pathlen', type=int, default=0)
    int_parser.add_argument('--log-file')
    int_parser.add_argument('--log-format', choices=['text', 'json'], default='text')
    int_parser.add_argument('--force', action='store_true')
    int_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory (for database)')
    int_parser.add_argument('--crl-url', action='append', help='CRL Distribution Point URL (can be multiple)')
    int_parser.add_argument('--ocsp-url', help='OCSP responder URL for AIA extension')

    # ca issue-cert
    cert_parser = ca_subparsers.add_parser('issue-cert', help='Issue an end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True)
    cert_parser.add_argument('--ca-key', required=True)
    cert_parser.add_argument('--ca-pass-file', required=True)
    cert_parser.add_argument('--template', choices=['server', 'client', 'code_signing'], required=True)
    cert_parser.add_argument('--subject', help='Distinguished Name (required unless --csr is provided)')
    cert_parser.add_argument('--san', action='append', help='SAN entry (e.g., dns:example.com)')
    cert_parser.add_argument('--out-dir', default='./pki/certs')
    cert_parser.add_argument('--validity-days', type=int, default=365)
    cert_parser.add_argument('--log-file')
    cert_parser.add_argument('--log-format', choices=['text', 'json'], default='text')
    cert_parser.add_argument('--csr', help='External CSR file (PEM). If provided, --subject is ignored and no private key is saved.')
    cert_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory (for database)')
    cert_parser.add_argument('--force', action='store_true', help='Overwrite existing output files')
    cert_parser.add_argument('--crl-url', action='append', help='CRL Distribution Point URL (can be multiple)')
    cert_parser.add_argument('--ocsp-url', help='OCSP responder URL for AIA extension')

    # ca issue-ocsp-cert
    ocsp_cert_parser = ca_subparsers.add_parser('issue-ocsp-cert', help='Issue OCSP signer certificate')
    ocsp_cert_parser.add_argument('--ca-cert', required=True)
    ocsp_cert_parser.add_argument('--ca-key', required=True)
    ocsp_cert_parser.add_argument('--ca-pass-file', required=True)
    ocsp_cert_parser.add_argument('--subject', required=True)
    ocsp_cert_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    ocsp_cert_parser.add_argument('--key-size', type=int, default=2048)  # RSA min 2048
    ocsp_cert_parser.add_argument('--san', action='append', help='DNS name or URI for responder')
    ocsp_cert_parser.add_argument('--out-dir', default='./pki/certs')
    ocsp_cert_parser.add_argument('--validity-days', type=int, default=365)
    ocsp_cert_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory (for database)')
    ocsp_cert_parser.add_argument('--log-file')
    ocsp_cert_parser.add_argument('--log-format', choices=['text', 'json'], default='text')
    ocsp_cert_parser.add_argument('--force', action='store_true')

    # client
    client_parser = subparsers.add_parser('client', help='Client tools')
    client_subparsers = client_parser.add_subparsers(dest='client_command', required=True)

    # client gen-csr
    gen_csr_parser = client_subparsers.add_parser('gen-csr', help='Generate private key and CSR')
    gen_csr_parser.add_argument('--subject', required=True)
    gen_csr_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    gen_csr_parser.add_argument('--key-size', type=int, default=2048, help='RSA: 2048/4096, ECC: 256/384')
    gen_csr_parser.add_argument('--san', action='append', help='SAN entry (dns:, ip:, email:, uri:)')
    gen_csr_parser.add_argument('--out-key', default='key.pem', help='Output private key file')
    gen_csr_parser.add_argument('--out-csr', default='request.csr.pem', help='Output CSR file')
    gen_csr_parser.add_argument('--force', action='store_true', help='Overwrite existing files')

    # client request-cert
    req_cert_parser = client_subparsers.add_parser('request-cert', help='Submit CSR to CA and get certificate')
    req_cert_parser.add_argument('--csr', required=True, help='CSR file')
    req_cert_parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    req_cert_parser.add_argument('--ca-url', required=True, help='Repository base URL (e.g., http://localhost:8080)')
    req_cert_parser.add_argument('--out-cert', default='cert.pem', help='Output certificate file')
    req_cert_parser.add_argument('--force', action='store_true', help='Overwrite existing certificate')

    # client validate (заглушка)
    validate_parser = client_subparsers.add_parser('validate', help='Validate certificate chain')
    validate_parser.add_argument('--cert', required=True)
    validate_parser.add_argument('--untrusted', action='append', help='Intermediate certificate file')
    validate_parser.add_argument('--trusted', default='./pki/certs/ca.cert.pem', help='Root CA certificate file')
    validate_parser.add_argument('--crl', help='CRL file or URL')
    validate_parser.add_argument('--ocsp', action='store_true', help='Perform OCSP check')
    validate_parser.add_argument('--mode', choices=['chain', 'full'], default='full')

    # client check-status (заглушка)
    check_parser = client_subparsers.add_parser('check-status', help='Check revocation status')
    check_parser.add_argument('--cert', required=True)
    check_parser.add_argument('--ca-cert', required=True, help='Issuer CA certificate')
    check_parser.add_argument('--crl', help='CRL file or URL')
    check_parser.add_argument('--ocsp-url', help='OCSP responder URL (overrides AIA)')

    # ca revoke
    revoke_parser = ca_subparsers.add_parser('revoke', help='Revoke a certificate')
    revoke_parser.add_argument('serial', help='Certificate serial number (hex)')
    revoke_parser.add_argument('--reason', default='unspecified',
                               choices=['unspecified', 'keyCompromise', 'cACompromise',
                                        'affiliationChanged', 'superseded', 'cessationOfOperation',
                                        'certificateHold', 'removeFromCRL', 'privilegeWithdrawn',
                                        'aACompromise'],
                               help='Revocation reason')
    revoke_parser.add_argument('--force', action='store_true', help='Skip confirmation prompts')
    revoke_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory (for database)')
    revoke_parser.add_argument('--log-file', help='Log file path')
    revoke_parser.add_argument('--log-format', choices=['text', 'json'], default='text')

    # ca gen-crl
    gen_crl_parser = ca_subparsers.add_parser('gen-crl', help='Generate CRL for a CA')
    gen_crl_parser.add_argument('--ca', required=True, choices=['root', 'intermediate'],
                                help='Which CA to generate CRL for (root or intermediate)')
    gen_crl_parser.add_argument('--next-update', type=int, default=7,
                                help='Days until next CRL update (default: 7)')
    gen_crl_parser.add_argument('--out-file', help='Output file path (default: <out-dir>/crl/<ca>.crl.pem)')
    gen_crl_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory')
    gen_crl_parser.add_argument('--log-file', help='Log file path')
    gen_crl_parser.add_argument('--log-format', choices=['text', 'json'], default='text')
    gen_crl_parser.add_argument('--force', action='store_true', help='Overwrite existing CRL file')
    gen_crl_parser.add_argument('--ca-pass-file', required=True,
                                help='File containing passphrase for CA private key')

    # ca check-revoked (опционально)
    check_revoked_parser = ca_subparsers.add_parser('check-revoked', help='Check revocation status of a certificate')
    check_revoked_parser.add_argument('serial', help='Certificate serial number (hex)')
    check_revoked_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory')
    check_revoked_parser.add_argument('--log-format', choices=['text', 'json'], default='text')

    # ca verify
    verify_parser = ca_subparsers.add_parser('verify', help='Verify a certificate')
    verify_parser.add_argument('--cert', required=True)

    # ca verify-chain
    chain_parser = ca_subparsers.add_parser('verify-chain', help='Validate certificate chain')
    chain_parser.add_argument('--leaf', required=True)
    chain_parser.add_argument('--root', required=True)
    chain_parser.add_argument('--intermediate', help='Intermediate CA certificate (PEM, optional)')

    # ca list-certs
    list_parser = ca_subparsers.add_parser('list-certs', help='List issued certificates')
    list_parser.add_argument('--status', choices=['valid', 'revoked', 'expired'], help='Filter by status')
    list_parser.add_argument('--format', default='table', choices=['table', 'json', 'csv'], help='Output format')
    list_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory (for database)')
    list_parser.add_argument('--limit', type=int, default=100)

    # ca show-cert
    show_parser = ca_subparsers.add_parser('show-cert', help='Show certificate by serial number')
    show_parser.add_argument('serial', help='Certificate serial number (hex)')
    show_parser.add_argument('--pki-dir', default='./pki', help='PKI root directory (for database)')

    # ---------- db ----------
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command', required=True)

    db_init = db_subparsers.add_parser('init', help='Initialize certificate database')
    db_init.add_argument('--out-dir', default='./pki', help='PKI root directory')
    db_init.add_argument('--log-format', choices=['text', 'json'], default='text')

    # ---------- repo ----------
    repo_parser = subparsers.add_parser('repo', help='Repository HTTP server')
    repo_subparsers = repo_parser.add_subparsers(dest='repo_command', required=True)

    repo_serve = repo_subparsers.add_parser('serve', help='Start HTTP server')
    repo_serve.add_argument('--host', default=None, help='Bind address')
    repo_serve.add_argument('--port', type=int, default=None, help='TCP port')
    repo_serve.add_argument('--out-dir', default=None, help='PKI root directory')
    repo_serve.add_argument('--log-file', help='Log file for HTTP requests')
    repo_serve.add_argument('--log-format', choices=['text', 'json'], default='text')
    repo_serve.add_argument('--ca-cert', help='CA certificate file for online signing')
    repo_serve.add_argument('--ca-key', help='CA private key file for online signing')
    repo_serve.add_argument('--ca-pass-file', help='Passphrase file for CA key')
    repo_serve.add_argument('--crl-url', action='append', help='Default CRL URL for issued certificates')
    repo_serve.add_argument('--ocsp-url', help='Default OCSP URL for issued certificates')

    repo_status = repo_subparsers.add_parser('status', help='Check if repository server is running')
    repo_status.add_argument('--host', default=None, help='Server host')
    repo_status.add_argument('--port', type=int, default=None, help='Server port')

    # ocsp
    ocsp_parser = subparsers.add_parser('ocsp', help='OCSP responder operations')
    ocsp_subparsers = ocsp_parser.add_subparsers(dest='ocsp_command', required=True)

    ocsp_serve_parser = ocsp_subparsers.add_parser('serve', help='Start OCSP responder server')
    ocsp_serve_parser.add_argument('--host', default='127.0.0.1', help='Bind address')
    ocsp_serve_parser.add_argument('--port', type=int, default=8081, help='TCP port')
    ocsp_serve_parser.add_argument('--db-path', default='./pki/micropki.db', help='SQLite database path')
    ocsp_serve_parser.add_argument('--responder-cert', required=True, help='OCSP signing certificate (PEM)')
    ocsp_serve_parser.add_argument('--responder-key', required=True, help='OCSP signing private key (PEM)')
    ocsp_serve_parser.add_argument('--ca-cert', required=True, help='Issuer CA certificate (PEM)')
    ocsp_serve_parser.add_argument('--cache-ttl', type=int, default=60, help='Response cache TTL in seconds')
    ocsp_serve_parser.add_argument('--log-file', help='Log file for OCSP requests')
    ocsp_serve_parser.add_argument('--log-format', choices=['text', 'json'], default='text')

    # ---------- parse arguments ----------
    args = parser.parse_args()

    # ---------- dispatch ----------
    if args.command == 'db':
        if args.db_command == 'init':
            db_path = Path(args.out_dir) / 'micropki.db'
            db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                database.migrate(str(db_path))
                print(f"Database initialized at {db_path}")
            except Exception as e:
                sys.stderr.write(f"Error initializing database: {e}\n")
                sys.exit(1)

    elif args.command == 'ca':
        if args.ca_command == 'init':
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.stderr.write("Error: RSA key size must be 4096\n")
                sys.exit(1)
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.stderr.write("Error: ECC key size must be 384\n")
                sys.exit(1)
            if not os.path.isfile(args.passphrase_file):
                sys.stderr.write(f"Error: Passphrase file '{args.passphrase_file}' does not exist\n")
                sys.exit(1)
            try:
                ca.init_ca(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    log_file=args.log_file,
                    force=args.force,
                    log_format=args.log_format
                )
                print("Root CA initialized successfully.")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)


        elif args.ca_command == 'issue-cert':
            if not args.csr and not args.subject:
                sys.stderr.write("Error: --subject is required when --csr is not provided.\n")
                sys.exit(1)
            for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
                if not os.path.isfile(f):
                    sys.stderr.write(f"Error: File not found: {f}\n")
                    sys.exit(1)
            try:
                ca.issue_certificate(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_pass_file=args.ca_pass_file,
                    template=args.template,
                    subject=args.subject,
                    san_list=args.san if args.san else [],
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    log_file=args.log_file,
                    csr_path=args.csr,
                    pki_dir=args.pki_dir,
                    log_format=args.log_format,
                    force=args.force,
                    crl_urls=args.crl_url,
                    ocsp_url=args.ocsp_url
                )
                print("Certificate issued successfully.")

            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)

        elif args.ca_command == 'issue-intermediate':
            # Проверка существования обязательных файлов
            for f in [args.root_cert, args.root_key, args.root_pass_file, args.passphrase_file]:
                if not os.path.isfile(f):
                    sys.stderr.write(f"Error: File not found: {f}\n")
                    sys.exit(1)
            try:
                ca.create_intermediate_ca(
                    root_cert_path=args.root_cert,
                    root_key_path=args.root_key,
                    root_pass_file=args.root_pass_file,
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    pathlen=args.pathlen,
                    log_file=args.log_file,
                    force=args.force,
                    pki_dir=args.pki_dir,
                    log_format=args.log_format,
                    crl_urls=args.crl_url,
                    ocsp_url=args.ocsp_url
                )
                print("Intermediate CA created successfully.")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)

        elif args.ca_command == 'verify':
            if not os.path.isfile(args.cert):
                sys.stderr.write(f"Error: Certificate file not found: {args.cert}\n")
                sys.exit(1)
            valid, msg = ca.verify_certificate(args.cert)
            if valid:
                print(msg)
            else:
                sys.stderr.write(f"Verification failed: {msg}\n")
                sys.exit(1)

        elif args.ca_command == 'verify-chain':
            if not os.path.isfile(args.leaf):
                sys.stderr.write(f"Error: Leaf certificate not found: {args.leaf}\n")
                sys.exit(1)
            if not os.path.isfile(args.root):
                sys.stderr.write(f"Error: Root certificate not found: {args.root}\n")
                sys.exit(1)
            if args.intermediate and not os.path.isfile(args.intermediate):
                sys.stderr.write(f"Error: Intermediate certificate not found: {args.intermediate}\n")
                sys.exit(1)
            valid, msg = ca.verify_chain(args.leaf, args.root, args.intermediate)
            if valid:
                print(msg)
            else:
                sys.stderr.write(f"Chain validation failed: {msg}\n")
                sys.exit(1)

        elif args.ca_command == 'list-certs':
            db_path = Path(args.pki_dir) / 'micropki.db'
            if not database.db_exists(str(db_path)):
                sys.stderr.write(f"Database not found at {db_path}. Run 'micropki db init' first.\n")
                sys.exit(1)
            certs = database.list_certs(str(db_path), status=args.status, limit=args.limit)
            if args.format == 'json':
                print(json.dumps(certs, indent=2))
            elif args.format == 'csv':
                if certs:
                    writer = csv.DictWriter(sys.stdout, fieldnames=certs[0].keys())
                    writer.writeheader()
                    writer.writerows(certs)
                else:
                    print("No certificates found.")
            else:  # table
                if certs:
                    print(f"{'Serial':<20} {'Subject':<40} {'Status':<10} {'Expires':<20}")
                    print("-" * 90)
                    for c in certs:
                        serial = c['serial_hex'][:18] + '…' if len(c['serial_hex']) > 20 else c['serial_hex']
                        subject = c['subject'][:38] + '…' if len(c['subject']) > 40 else c['subject']
                        expires = c['not_after'][:10] if 'not_after' in c else ''
                        print(f"{serial:<20} {subject:<40} {c['status']:<10} {expires}")
                else:
                    print("No certificates found.")

        elif args.ca_command == 'show-cert':
            db_path = Path(args.pki_dir) / 'micropki.db'
            if not database.db_exists(str(db_path)):
                sys.stderr.write(f"Database not found at {db_path}. Run 'micropki db init' first.\n")
                sys.exit(1)
            serial_arg = args.serial
            if not serial_arg.startswith('0x'):
                serial_arg = '0x' + serial_arg
            cert_data = database.get_cert_by_serial(str(db_path), serial_arg)
            if cert_data:
                print(cert_data['cert_pem'])
            else:
                sys.stderr.write(f"Certificate with serial {args.serial} not found.\n")
                sys.exit(1)

        elif args.ca_command == 'revoke':
            from . import revocation
            db_path = Path(args.pki_dir) / 'micropki.db'
            # Применяем миграции
            database.migrate(str(db_path))
            if not database.db_exists(str(db_path)):
                sys.stderr.write(f"Database not found at {db_path}. Run 'micropki db init' first.\n")
                sys.exit(1)
            try:
                revocation.revoke_certificate(
                    str(db_path), args.serial, reason=args.reason, force=args.force,
                    log_file=args.log_file, log_format=args.log_format
                )
                print(f"Certificate {args.serial} revoked successfully.")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)


        elif args.ca_command == 'gen-crl':
            from . import crl
            pki_dir = Path(args.pki_dir)
            db_path = pki_dir / 'micropki.db'
            # Применяем миграции перед работой
            database.migrate(str(db_path))
            certs_dir = pki_dir / 'certs'
            private_dir = pki_dir / 'private'
            crl_dir = pki_dir / 'crl'
            crl_dir.mkdir(exist_ok=True, parents=True)
            if args.ca == 'root':
                ca_cert = certs_dir / 'ca.cert.pem'
                ca_key = private_dir / 'ca.key.pem'
                default_crl_file = crl_dir / 'root.crl.pem'
            else:  # intermediate
                ca_cert = certs_dir / 'intermediate.cert.pem'
                ca_key = private_dir / 'intermediate.key.pem'
                default_crl_file = crl_dir / 'intermediate.crl.pem'
            if not ca_cert.exists() or not ca_key.exists():
                sys.stderr.write(f"CA certificate or key not found for {args.ca}\n")
                sys.exit(1)
            ca_pass_file = args.ca_pass_file
            if not os.path.isfile(ca_pass_file):
                sys.stderr.write(f"CA passphrase file not found: {ca_pass_file}\n")
                sys.exit(1)
            out_file = args.out_file if args.out_file else str(default_crl_file)
            if os.path.exists(out_file) and not args.force:
                sys.stderr.write(f"CRL file {out_file} already exists. Use --force to overwrite.\n")
                sys.exit(1)
            try:
                crl.generate_crl(
                    db_path=str(db_path),
                    ca_cert_path=str(ca_cert),
                    ca_key_path=str(ca_key),
                    ca_pass_file=ca_pass_file,
                    out_file=out_file,
                    next_update_days=args.next_update,
                    log_file=args.log_file,
                    log_format=args.log_format
                )
                print(f"CRL generated for {args.ca} CA: {out_file}")
            except Exception as e:
                sys.stderr.write(f"Error generating CRL: {e}\n")
                sys.exit(1)

        elif args.ca_command == 'check-revoked':
            db_path = Path(args.pki_dir) / 'micropki.db'
            if not database.db_exists(str(db_path)):
                sys.stderr.write(f"Database not found at {db_path}\n")
                sys.exit(1)
            serial_hex = args.serial if args.serial.startswith('0x') else '0x' + args.serial
            cert = database.get_cert_by_serial(str(db_path), serial_hex)
            if not cert:
                print(f"Certificate {args.serial} not found")
                sys.exit(1)
            if cert['status'] == 'revoked':
                print(
                    f"Certificate {args.serial} is REVOKED. Reason: {cert['revocation_reason']}, Date: {cert['revocation_date']}")
            else:
                print(f"Certificate {args.serial} is {cert['status']} (not revoked)")


        elif args.ca_command == 'issue-ocsp-cert':
            # Проверка ключей и файлов
            if args.key_type == 'rsa' and args.key_size < 2048:
                sys.stderr.write("Error: RSA key size must be at least 2048\n")
                sys.exit(1)
            if args.key_type == 'ecc' and args.key_size < 256:
                sys.stderr.write("Error: ECC key size must be at least 256\n")
                sys.exit(1)
            for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
                if not os.path.isfile(f):
                    sys.stderr.write(f"Error: File not found: {f}\n")
                    sys.exit(1)

            # Подготовка БД
            db_path = Path(args.pki_dir) / 'micropki.db'
            database.migrate(str(db_path))
            try:
                san_list = args.san if args.san else []
                cert_path, key_path = ca.issue_certificate(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_pass_file=args.ca_pass_file,
                    template='ocsp_signer',
                    subject=args.subject,
                    san_list=san_list,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    log_file=args.log_file,
                    pki_dir=args.pki_dir,
                    log_format=args.log_format,
                    force=args.force
                )
                print(f"OCSP signer certificate issued: {cert_path}")
                print(f"Private key (unencrypted) saved to: {key_path}")
                print("WARNING: OCSP private key is stored unencrypted! Ensure proper file permissions.")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)

    elif args.command == 'repo':
        cfg = load_config()
        if args.repo_command == 'serve':
            host = args.host if args.host is not None else cfg['host']
            port = args.port if args.port is not None else cfg['port']
            out_dir = args.out_dir if args.out_dir is not None else cfg['pki_dir']
            from .repository import create_app
            app = create_app(
                out_dir,
                args.log_file,
                log_format=args.log_format,
                ca_cert_path=args.ca_cert,
                ca_key_path=args.ca_key,
                ca_pass_file=args.ca_pass_file,
                crl_urls=args.crl_url,
                ocsp_url=args.ocsp_url
            )
            app.run(host=host, port=port, debug=False)
        elif args.repo_command == 'status':
            host = args.host if args.host is not None else cfg['host']
            port = args.port if args.port is not None else cfg['port']
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"Repository server is running on {host}:{port}")
            else:
                print(f"Repository server is NOT running on {host}:{port}")
            sock.close()

    elif args.command == 'ocsp':
        if args.ocsp_command == 'serve':
            from .ocsp_responder import create_ocsp_app
            app = create_ocsp_app(
                db_path=args.db_path,
                responder_cert_path=args.responder_cert,
                responder_key_path=args.responder_key,
                ca_cert_path=args.ca_cert,
                cache_ttl=args.cache_ttl,
                log_file=args.log_file,
                log_format=args.log_format
            )
            app.run(host=args.host, port=args.port, debug=False)


    elif args.command == 'client':
        from . import client
        if args.client_command == 'gen-csr':
            try:
                key_path, csr_path = client.generate_csr(
                    subject=args.subject,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    san_list=args.san or [],
                    out_key=args.out_key,
                    out_csr=args.out_csr,
                    force=args.force
                )
                print(f"Private key saved to {key_path}")
                print(f"CSR saved to {csr_path}")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)
        elif args.client_command == 'request-cert':
            try:
                cert_path = client.request_cert(
                    csr_path=args.csr,
                    template=args.template,
                    ca_url=args.ca_url,
                    out_cert=args.out_cert,
                    force=args.force
                )
                print(f"Certificate saved to {cert_path}")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)
        elif args.client_command == 'validate':
            try:
                result = client.validate_cert(
                    cert_path=args.cert,
                    intermediates=args.untrusted,
                    trust_store=args.trusted,
                    crl_source=args.crl,
                    ocsp_source=args.ocsp_url if args.ocsp else None,
                    mode=args.mode
                )
                if result['valid']:
                    print(f"[OK] {result['message']}")
                else:
                    sys.stderr.write(f"[FAIL] {result['message']}\n")
                    sys.exit(1)
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)
        elif args.client_command == 'check-status':
            try:
                status = client.check_status_cli(
                    cert_path=args.cert,
                    ca_cert_path=args.ca_cert,
                    crl_source=args.crl,
                    ocsp_url=args.ocsp_url
                )
                print(f"Status: {status['status']}")
                if status.get('reason'):
                    print(f"Reason: {status['reason']}")
                if status.get('revocation_time'):
                    print(f"Revocation time: {status['revocation_time']}")
                if status['status'] != 'good':
                    sys.exit(1)
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()