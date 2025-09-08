"""
DIVYASTRA Configuration Management
Advanced configuration system for next-generation web penetration testing
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

log = logging.getLogger(__name__)

class Config:
    """DIVYASTRA Configuration Manager"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config_data = self._load_default_config()
        
        # Load from file if exists
        if Path(self.config_file).exists():
            self.load_from_file(self.config_file)
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        config_dir = Path.home() / '.divyastra'
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / 'config.json')
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            "version": "2.0.0-nextgen",
            "reconnaissance": {
                "max_workers": 10,
                "timeout": 10,
                "max_retries": 3,
                "enable_subdomain_enum": True,
                "enable_port_scan": True,
                "enable_tech_detection": True,
                "enable_certificate_transparency": True,
                "enable_osint": True,
                "deep_js_analysis": False,
                "subdomain_wordlist": None,
                "port_range": "common"
            },
            "security_testing": {
                "enable_injection_testing": True,
                "enable_auth_testing": True,
                "enable_business_logic": False,
                "enable_api_security": True,
                "enable_graphql_testing": True,
                "enable_websocket_testing": False,
                "injection_payloads": None,
                "business_logic_workflows": False,
                "timing_attack_threshold": 0.5
            },
            "ai_capabilities": {
                "enable_ai_payloads": False,
                "ai_provider": "openai",
                "ai_model": "gpt-4",
                "confidence_threshold": 80,
                "auto_poc_generation": False,
                "intelligent_fuzzing": False,
                "pattern_recognition": False,
                "openai_api_key": None,
                "max_ai_calls": 100
            },
            "zero_day_hunting": {
                "enable_static_analysis": False,
                "enable_dynamic_analysis": False,
                "enable_intelligent_fuzzing": False,
                "pattern_mining": False,
                "novelty_threshold": 70,
                "enable_poc_synthesis": False,
                "budget": 1000
            },
            "warfare_simulation": {
                "enable_apt_simulation": False,
                "apt_scenarios": ["chinese", "russian", "insider"],
                "sandbox_type": "docker",
                "enable_mitre_mapping": True,
                "containment_level": "full"
            },
            "reporting": {
                "formats": ["json"],
                "include_evidence": True,
                "include_screenshots": False,
                "include_poc_code": False,
                "generate_dashboard": False,
                "generate_executive_summary": False,
                "compliance_frameworks": [],
                "output_directory": "./reports"
            },
            "performance": {
                "concurrent_requests": 20,
                "dns_timeout": 3,
                "http_timeout": 10,
                "max_redirects": 5,
                "connection_pooling": True,
                "request_caching": False,
                "async_processing": True,
                "memory_optimization": True
            },
            "logging": {
                "level": "INFO",
                "file": None,
                "max_size": "10MB",
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }
    
    def load_from_file(self, config_file: str) -> bool:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            
            # Merge with default configuration
            self._merge_config(self.config_data, file_config)
            
            log.info(f"Configuration loaded from {config_file}")
            return True
            
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log.error(f"Failed to load configuration from {config_file}: {e}")
            return False
    
    def save_to_file(self, config_file: Optional[str] = None) -> bool:
        """Save configuration to JSON file"""
        target_file = config_file or self.config_file
        
        try:
            # Ensure directory exists
            Path(target_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(target_file, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, indent=2, ensure_ascii=False)
            
            log.info(f"Configuration saved to {target_file}")
            return True
            
        except Exception as e:
            log.error(f"Failed to save configuration to {target_file}: {e}")
            return False
    
    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        target = self.config_data
        
        # Navigate to parent dictionary
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        
        # Set the final value
        target[keys[-1]] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration"""
        return self.config_data.copy()
    
    def get_recon_config(self) -> Dict[str, Any]:
        """Get reconnaissance-specific configuration"""
        return self.get('reconnaissance', {})
    
    def get_ai_config(self) -> Dict[str, Any]:
        """Get AI capabilities configuration"""
        return self.get('ai_capabilities', {})
    
    def get_zero_day_config(self) -> Dict[str, Any]:
        """Get zero-day hunting configuration"""
        return self.get('zero_day_hunting', {})
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration"""
        return self.get('reporting', {})
    
    def is_ai_enabled(self) -> bool:
        """Check if AI capabilities are enabled"""
        return self.get('ai_capabilities.enable_ai_payloads', False)
    
    def is_zero_day_enabled(self) -> bool:
        """Check if zero-day hunting is enabled"""
        return (self.get('zero_day_hunting.enable_static_analysis', False) or
                self.get('zero_day_hunting.enable_dynamic_analysis', False))
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate AI configuration
        if self.is_ai_enabled():
            if not self.get('ai_capabilities.openai_api_key'):
                issues.append("AI capabilities enabled but no OpenAI API key configured")
        
        # Validate paths
        output_dir = self.get('reporting.output_directory')
        if output_dir and not Path(output_dir).parent.exists():
            issues.append(f"Output directory parent does not exist: {output_dir}")
        
        # Validate numeric values
        max_workers = self.get('reconnaissance.max_workers')
        if not isinstance(max_workers, int) or max_workers < 1 or max_workers > 100:
            issues.append("reconnaissance.max_workers must be between 1 and 100")
        
        timeout = self.get('reconnaissance.timeout')
        if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 300:
            issues.append("reconnaissance.timeout must be between 1 and 300 seconds")
        
        return issues


def get_config() -> Config:
    """Get global configuration instance"""
    if not hasattr(get_config, '_instance'):
        get_config._instance = Config()
    return get_config._instance
