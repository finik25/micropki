import argparse
import sys
import os
from . import ca

def main():
    parser = argparse.ArgumentParser(description='MicroPKI - Minimal PKI Tool')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # ca init subcommand
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', required=True)
    init_parser = ca_subparsers.add_parser('init', help='Initialize Root CA')

    init_parser.add_argument('--subject', required=True, help='Distinguished Name (e.g., "/CN=Root CA" or "CN=Root CA,O=Demo")')
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type (rsa or ecc)')
    init_parser.add_argument('--key-size', type=int, default=4096, help='Key size (RSA: 4096, ECC: 384)')
    init_parser.add_argument('--passphrase-file', required=True, help='File containing passphrase for key encryption')
    init_parser.add_argument('--out-dir', default='./pki', help='Output directory (default: ./pki)')
    init_parser.add_argument('--validity-days', type=int, default=3650, help='Validity period in days (default: 3650)')
    init_parser.add_argument('--log-file', help='Optional log file path (logs to stderr if not provided)')
    init_parser.add_argument('--force', action='store_true', help='Overwrite existing files')

    args = parser.parse_args()

    if args.command == 'ca' and args.ca_command == 'init':
        # Validate key size consistency
        if args.key_type == 'rsa' and args.key_size != 4096:
            sys.stderr.write(f"Error: RSA key size must be 4096, got {args.key_size}\n")
            sys.exit(1)
        if args.key_type == 'ecc' and args.key_size != 384:
            sys.stderr.write(f"Error: ECC key size must be 384, got {args.key_size}\n")
            sys.exit(1)

        # Check passphrase file existence
        if not os.path.isfile(args.passphrase_file):
            sys.stderr.write(f"Error: Passphrase file '{args.passphrase_file}' does not exist\n")
            sys.exit(1)

        # Check output directory writability (will be created if needed)
        out_dir = args.out_dir
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            sys.stderr.write(f"Error: Cannot create output directory '{out_dir}': {e}\n")
            sys.exit(1)

        # Run CA init
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
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()