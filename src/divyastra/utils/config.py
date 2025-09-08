import os
import json
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

class Config:
    """DIVYASTRA Configuration Management"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config_data = self._load_default_config()
        self._load_config_file()

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        config_dir = home_dir / '.divyastra'
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / 'config.yaml')

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'general': {
                'version': '1.0.0',
                'debug': False,
                'log_level': 'INFO',
                'max_threads': 20,
                'timeout': 30,
                'user_agent': 'DIVYASTRA/1.0 (Automated Security Scanner)',
                'air_gapped_mode': False
            },
            'scanning': {
                'default_aggression': 'medium',
                'default_scope': ['web'],
                'max_budget_per_scan': 1000,
                'enable_sandboxing': True,
                'sandbox_timeout': 300,
                'max_concurrent_exploits': 5,
                'enable_post_validation': True
            },
            'reconnaissance': {
                'enable_subdomain_enum': True,
                'enable_port_scanning': True,
                'enable_tech_detection': True,
                'enable_osint': True,
                'enable_certificate_transparency': True,
                'max_subdomains': 1000,
                'port_scan_timeout': 3,
                'common_ports_only': True
            },
            'vulnerability_feeds': {
                'auto_update': True,
                'update_interval': 3600,
                'enabled_feeds': ['cve', 'exploitdb', 'owasp'],
                'feed_endpoints': {
                    'cve': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                    'exploitdb': 'https://www.exploit-db.com/',
                    'owasp': 'https://owasp.org/www-community/vulnerabilities/'
                },
                'custom_feeds': []
            },
            'ai': {
                'enable_ai_payloads': False,
                'ai_provider': 'openai',  # openai, huggingface, local
                'model': 'gpt-3.5-turbo',
                'max_tokens': 1000,
                'temperature': 0.7,
                'enable_payload_adaptation': True,
                'enable_chain_generation': True
            },
            'reporting': {
                'default_format': 'pdf',
                'default_template': 'technical',
                'include_executive_summary': True,
                'include_technical_details': True,
                'include_poc': True,
                'output_directory': './reports',
                'auto_timestamp': True,
                'compliance_frameworks': ['nist', 'owasp', 'pci-dss']
            },
            'compliance': {
                'enable_audit_mode': False,
                'log_all_actions': True,
                'require_approval': False,
                'max_impact_level': 'medium',
                'forbidden_actions': [],
                'whitelist_only': False,
                'approved_targets': []
            },
            'api_keys': {
                'shodan': '',
                'censys_id': '',
                'censys_secret': '',
                'virustotal': '',
                'openai': '',
                'have_i_been_pwned': ''
            },
            'network': {
                'proxy_enabled': False,
                'proxy_url': '',
                'proxy_auth': '',
                'verify_ssl': True,
                'custom_dns': [],
                'rate_limit': 10,  # requests per second
                'retry_attempts': 3
            },
            'localization': {
                'language': 'en',
                'timezone': 'UTC',
                'date_format': '%Y-%m-%d %H:%M:%S',
                'currency': 'USD'
            }
        }

    def _load_config_file(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                        file_config = yaml.safe_load(f)
                    else:
                        file_config = json.load(f)
                
                # Merge file config with default config
                self._deep_merge(self.config_data, file_config)
                
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
                print("Using default configuration...")

    def _deep_merge(self, base_dict: Dict, update_dict: Dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value

    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value

    def save(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                    yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config_data, f, indent=2)
                    
        except Exception as e:
            print(f"Error saving config file: {e}")

    def is_air_gapped(self) -> bool:
        """Check if running in air-gapped mode"""
        return self.get('general.air_gapped_mode', False)

    def is_compliance_mode(self) -> bool:
        """Check if running in compliance/audit mode"""
        return self.get('compliance.enable_audit_mode', False)

    def get_api_key(self, service: str) -> str:
        """Get API key for a specific service"""
        return self.get(f'api_keys.{service}', '')

# Global configuration instance
_config = None

def get_config() -> Config:
    """Get global configuration instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config