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

def load_config(config_file='micropki.conf' or 'config.yaml'):
    """Load configuration from YAML file if exists, otherwise return defaults."""
    config = DEFAULT_CONFIG.copy()
    config_path = Path(config_file)
    if config_path.exists():
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            if user_config:
                config.update(user_config)
    return config