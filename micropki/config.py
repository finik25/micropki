import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    'pki_dir': './pki',
    'db_path': './pki/micropki.db',
    'host': '127.0.0.1',
    'port': 8080,
    'log_level': 'INFO'
}

# Политики безопасности (можно переопределить в конфигурационном файле)
POLICY_MAX_VALIDITY_DAYS = {
    'root': 3650,
    'intermediate': 1825,
    'end_entity': 365
}
POLICY_MIN_KEY_SIZE = {
    'rsa_root': 4096,
    'rsa_intermediate': 3072,
    'rsa_end_entity': 2048,
    'ecc_root': 384,
    'ecc_intermediate': 384,
    'ecc_end_entity': 256
}
POLICY_FORBIDDEN_WILDCARD = True   # запрещать wildcard в SAN для server
POLICY_ALLOWED_SAN_TYPES = {
    'server': {'dns', 'ip'},
    'client': {'email', 'dns'},
    'code_signing': {'dns', 'uri'},
    'ocsp_signer': {'dns', 'uri'}
}

def load_config(config_file='micropki.conf'):
    """Load configuration from YAML file if exists, otherwise return defaults."""
    config = DEFAULT_CONFIG.copy()
    config_path = Path(config_file)
    if config_path.exists():
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            if user_config:
                config.update(user_config)
    return config