"""
DIVYASTRA Scope Management
Target scope definition and validation for penetration testing
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Set, Optional, Union
import logging

log = logging.getLogger(__name__)

class Scope:
    """Target scope management for DIVYASTRA"""
    
    def __init__(self, target: str, include_subdomains: bool = True):
        self.original_target = target
        self.target = self._normalize_target(target)
        self.include_subdomains = include_subdomains
        
        # Scope boundaries
        self.allowed_domains: Set[str] = set()
        self.allowed_ips: Set[str] = set()
        self.excluded_domains: Set[str] = set()
        self.excluded_ips: Set[str] = set()
        
        # Initialize scope
        self._initialize_scope()
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target format"""
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc
        
        # Remove port if present
        if ':' in target and not self._is_ipv6(target):
            target = target.split(':')[0]
        
        return target.lower().strip()
    
    def _is_ipv6(self, target: str) -> bool:
        """Check if target is IPv6 address"""
        try:
            ipaddress.IPv6Address(target)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def _initialize_scope(self):
        """Initialize scope based on target"""
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(self.target)
            self.allowed_ips.add(str(ip))
            log.debug(f"Added IP to scope: {ip}")
            
        except ipaddress.AddressValueError:
            # It's a domain name
            self.allowed_domains.add(self.target)
            log.debug(f"Added domain to scope: {self.target}")
            
            # Add subdomains if enabled
            if self.include_subdomains:
                self.allowed_domains.add(f"*.{self.target}")
                log.debug(f"Added wildcard subdomain to scope: *.{self.target}")
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is within scope"""
        normalized = self._normalize_target(target)
        
        # Check exclusions first
        if self._is_excluded(normalized):
            return False
        
        # Check if it's an allowed IP
        try:
            ip = ipaddress.ip_address(normalized)
            return str(ip) in self.allowed_ips
        except ipaddress.AddressValueError:
            pass
        
        # Check if it's an allowed domain
        return self._is_domain_allowed(normalized)
    
    def _is_excluded(self, target: str) -> bool:
        """Check if target is explicitly excluded"""
        # Check excluded IPs
        try:
            ip = ipaddress.ip_address(target)
            return str(ip) in self.excluded_ips
        except ipaddress.AddressValueError:
            pass
        
        # Check excluded domains
        for excluded in self.excluded_domains:
            if excluded.startswith('*.'):
                # Wildcard exclusion
                domain = excluded[2:]
                if target == domain or target.endswith(f".{domain}"):
                    return True
            elif target == excluded:
                return True
        
        return False
    
    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if domain is allowed"""
        for allowed in self.allowed_domains:
            if allowed.startswith('*.'):
                # Wildcard match
                base_domain = allowed[2:]
                if domain == base_domain or domain.endswith(f".{base_domain}"):
                    return True
            elif domain == allowed:
                return True
        
        return False
    
    def add_allowed_domain(self, domain: str):
        """Add domain to allowed scope"""
        normalized = self._normalize_target(domain)
        self.allowed_domains.add(normalized)
        log.debug(f"Added allowed domain: {normalized}")
    
    def add_allowed_ip(self, ip: str):
        """Add IP to allowed scope"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            self.allowed_ips.add(str(ip_obj))
            log.debug(f"Added allowed IP: {ip_obj}")
        except ipaddress.AddressValueError:
            log.warning(f"Invalid IP address: {ip}")
    
    def add_excluded_domain(self, domain: str):
        """Add domain to exclusion list"""
        normalized = self._normalize_target(domain)
        self.excluded_domains.add(normalized)
        log.debug(f"Added excluded domain: {normalized}")
    
    def add_excluded_ip(self, ip: str):
        """Add IP to exclusion list"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            self.excluded_ips.add(str(ip_obj))
            log.debug(f"Added excluded IP: {ip_obj}")
        except ipaddress.AddressValueError:
            log.warning(f"Invalid IP address: {ip}")
    
    def get_scope_summary(self) -> dict:
        """Get summary of current scope"""
        return {
            'target': self.target,
            'original_target': self.original_target,
            'include_subdomains': self.include_subdomains,
            'allowed_domains': list(self.allowed_domains),
            'allowed_ips': list(self.allowed_ips),
            'excluded_domains': list(self.excluded_domains),
            'excluded_ips': list(self.excluded_ips)
        }
    
    def validate_targets(self, targets: List[str]) -> List[str]:
        """Validate list of targets against scope"""
        valid_targets = []
        
        for target in targets:
            if self.is_in_scope(target):
                valid_targets.append(target)
            else:
                log.warning(f"Target out of scope: {target}")
        
        return valid_targets
