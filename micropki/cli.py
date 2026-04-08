import argparse
import sys
import os
from . import ca

def main():
    parser = argparse.ArgumentParser(description='MicroPKI - Minimal PKI Tool')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # ca parent parser
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', required=True)

    # ca init (Sprint 1)
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')
    init_parser.add_argument('--subject', required=True)
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    init_parser.add_argument('--key-size', type=int, default=4096)
    init_parser.add_argument('--passphrase-file', required=True)
    init_parser.add_argument('--out-dir', default='./pki')
    init_parser.add_argument('--validity-days', type=int, default=3650)
    init_parser.add_argument('--log-file')
    init_parser.add_argument('--force', action='store_true')

    # ca issue-intermediate (Sprint 2)
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
    int_parser.add_argument('--force', action='store_true')

    # ca issue-cert (Sprint 2)
    cert_parser = ca_subparsers.add_parser('issue-cert', help='Issue an end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True)
    cert_parser.add_argument('--ca-key', required=True)
    cert_parser.add_argument('--ca-pass-file', required=True)
    cert_parser.add_argument('--template', choices=['server', 'client', 'code_signing'], required=True)
    cert_parser.add_argument('--subject', required=True)
    cert_parser.add_argument('--san', action='append', help='SAN entry (e.g., dns:example.com)')
    cert_parser.add_argument('--out-dir', default='./pki/certs')
    cert_parser.add_argument('--validity-days', type=int, default=365)
    cert_parser.add_argument('--log-file')
    cert_parser.add_argument('--csr',
                             help='External CSR file (PEM). If provided, --subject is ignored and no private key is saved.')

    # ca verify (Sprint 1)
    verify_parser = ca_subparsers.add_parser('verify', help='Verify a certificate')
    verify_parser.add_argument('--cert', required=True)

    chain_parser = ca_subparsers.add_parser('verify-chain', help='Validate certificate chain')
    chain_parser.add_argument('--leaf', required=True, help='Leaf certificate (PEM)')
    chain_parser.add_argument('--root', required=True, help='Root CA certificate (PEM)')
    chain_parser.add_argument('--intermediate', help='Intermediate CA certificate (PEM, optional)')

    args = parser.parse_args()

    if args.command == 'ca':
        if args.ca_command == 'init':
            # validation as before
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.stderr.write(f"Error: RSA key size must be 4096\n")
                sys.exit(1)
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.stderr.write(f"Error: ECC key size must be 384\n")
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
                    force=args.force
                )
                print("Root CA initialized successfully.")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)

        elif args.ca_command == 'issue-intermediate':
            # validate key size
            if args.key_type == 'rsa' and args.key_size != 4096:
                sys.stderr.write("Error: RSA key size must be 4096\n")
                sys.exit(1)
            if args.key_type == 'ecc' and args.key_size != 384:
                sys.stderr.write("Error: ECC key size must be 384\n")
                sys.exit(1)
            # check files exist
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
                    force=args.force
                )
                print("Intermediate CA created successfully.")
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.exit(1)

        elif args.ca_command == 'issue-cert':
            # check files
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
                    log_file=args.log_file
                )
                print("Certificate issued successfully.")
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

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()