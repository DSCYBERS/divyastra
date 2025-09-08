import asyncio
import json
import logging
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse

import httpx
import xmltodict
from shodan import Shodan

from ..core.agent import Agent
from ..core.event_bus import EventBus
from ..core.scope import Scope

log = logging.getLogger(__name__)

class WebReconAgent(Agent):
    """Next-generation asynchronous web reconnaissance agent"""
    
    def __init__(self, bus: EventBus, scope: Scope, budget: int):
        super().__init__(bus, scope, budget)
        self.results = {
            'target': scope.target,
            'subdomains': set(),
            'ports': [],
            'technologies': [],
            'osint': {},
            'certificates': [],
            'ips': set(),
            'timestamp': int(time.time())
        }
        self.budget_used = 0
        
        # API clients
        self.shodan_client = None
        self.http_client = None
        
    async def execute(self) -> None:
        """Execute comprehensive web reconnaissance"""
        log.info(f"🚀 Starting next-gen web recon on {self.scope.target}")
        
        try:
            # Initialize HTTP client
            self.http_client = httpx.AsyncClient(timeout=30.0)
            
            # Initialize Shodan client if API key available
            await self._init_shodan()
            
            # Execute reconnaissance phases
            await self._check_budget("Starting reconnaissance")
            
            # Phase 1: Subdomain enumeration
            await self._subdomain_enumeration()
            await self._emit_subdomains()
            
            # Phase 2: Port scanning
            await self._port_scanning()
            await self._emit_ports()
            
            # Phase 3: Technology fingerprinting
            await self._technology_fingerprinting()
            await self._emit_technologies()
            
            # Phase 4: OSINT collection
            await self._osint_collection()
            await self._emit_osint()
            
            log.info(f"✅ Reconnaissance completed for {self.scope.target}")
            
        except Exception as e:
            log.error(f"❌ Reconnaissance failed: {str(e)}")
            raise
        finally:
            if self.http_client:
                await self.http_client.aclose()
    
    async def _init_shodan(self):
        """Initialize Shodan client if API key is available"""
        try:
            # Check for Shodan API key in environment or config
            import os
            api_key = os.getenv('SHODAN_API_KEY')
            if api_key:
                self.shodan_client = Shodan(api_key)
                log.info("🔑 Shodan client initialized")
            else:
                log.warning("⚠️  Shodan API key not found, skipping Shodan queries")
        except Exception as e:
            log.warning(f"⚠️  Failed to initialize Shodan client: {str(e)}")
    
    async def _check_budget(self, operation: str) -> None:
        """Check if budget allows for operation"""
        if self.budget_used >= self.budget:
            raise RuntimeError(f"Budget exceeded during: {operation}")
        log.debug(f"Budget: {self.budget_used}/{self.budget} - {operation}")
    
    async def _subdomain_enumeration(self) -> None:
        """Enumerate subdomains using subfinder"""
        log.info("  📡 Enumerating subdomains with subfinder...")
        
        try:
            await self._check_budget("Subdomain enumeration")
            
            # Run subfinder
            cmd = [
                'subfinder',
                '-d', self.scope.target,
                '-silent',
                '-o', '/dev/stdout'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                subdomains = [s.strip() for s in subdomains if s.strip()]
                
                for subdomain in subdomains:
                    if self._is_in_scope(subdomain):
                        self.results['subdomains'].add(subdomain)
                
                log.info(f"    ✅ Found {len(self.results['subdomains'])} subdomains")
                self.budget_used += 1
                
            else:
                log.warning(f"    ⚠️  Subfinder failed: {stderr.decode()}")
                
                # Fallback to basic DNS enumeration
                await self._basic_subdomain_enum()
                
        except FileNotFoundError:
            log.warning("    ⚠️  Subfinder not found, using basic enumeration")
            await self._basic_subdomain_enum()
        except Exception as e:
            log.error(f"    ❌ Subdomain enumeration failed: {str(e)}")
    
    async def _basic_subdomain_enum(self) -> None:
        """Basic subdomain enumeration fallback"""
        log.info("    📡 Using basic subdomain enumeration...")
        
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'portal', 'support', 'secure', 'vpn',
            'cdn', 'static', 'assets', 'images', 'm', 'mobile', 'beta'
        ]
        
        # Create semaphore to limit concurrent DNS queries
        semaphore = asyncio.Semaphore(10)
        
        async def check_subdomain(sub: str) -> Optional[str]:
            async with semaphore:
                try:
                    subdomain = f"{sub}.{self.scope.target}"
                    # Use nslookup for basic DNS resolution
                    process = await asyncio.create_subprocess_exec(
                        'nslookup', subdomain,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await process.communicate()
                    
                    if process.returncode == 0 and 'NXDOMAIN' not in stdout.decode():
                        return subdomain
                except Exception:
                    pass
                return None
        
        # Check all common subdomains concurrently
        tasks = [check_subdomain(sub) for sub in common_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str) and self._is_in_scope(result):
                self.results['subdomains'].add(result)
        
        log.info(f"    ✅ Basic enumeration found {len(self.results['subdomains'])} subdomains")
    
    async def _port_scanning(self) -> None:
        """Perform port scanning using nmap"""
        log.info("  🔍 Scanning ports with nmap...")
        
        try:
            await self._check_budget("Port scanning")
            
            # Get all targets (main domain + subdomains)
            targets = [self.scope.target] + list(self.results['subdomains'])
            
            for target in targets[:5]:  # Limit to 5 targets for budget
                await self._scan_target_ports(target)
            
            log.info(f"    ✅ Found {len(self.results['ports'])} open ports")
            self.budget_used += 2
            
        except Exception as e:
            log.error(f"    ❌ Port scanning failed: {str(e)}")
    
    async def _scan_target_ports(self, target: str) -> None:
        """Scan ports for a specific target"""
        try:
            # Common ports to scan
            port_range = "22,25,53,80,110,143,443,993,995,3306,5432,8080,8443,9200"
            
            cmd = [
                'nmap',
                '-sV',  # Service version detection
                '-Pn',  # Skip ping
                '-p', port_range,
                '--open',  # Only show open ports
                '-oX', '-',  # Output XML to stdout
                target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                await self._parse_nmap_xml(stdout.decode(), target)
            else:
                log.warning(f"    ⚠️  Nmap scan failed for {target}: {stderr.decode()}")
                
        except FileNotFoundError:
            log.warning(f"    ⚠️  Nmap not found, using basic port check for {target}")
            await self._basic_port_scan(target)
        except Exception as e:
            log.warning(f"    ⚠️  Port scan failed for {target}: {str(e)}")
    
    async def _parse_nmap_xml(self, xml_data: str, target: str) -> None:
        """Parse nmap XML output"""
        try:
            # Parse XML
            root = ET.fromstring(xml_data)
            
            for host in root.findall('.//host'):
                # Get IP address
                address = host.find('.//address[@addrtype="ipv4"]')
                if address is not None:
                    ip = address.get('addr')
                    self.results['ips'].add(ip)
                
                # Get open ports
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_num = port.get('portid')
                        protocol = port.get('protocol')
                        
                        # Get service info
                        service = port.find('service')
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        service_version = service.get('version', '') if service is not None else ''
                        
                        port_info = {
                            'target': target,
                            'port': int(port_num),
                            'protocol': protocol,
                            'service': service_name,
                            'version': service_version,
                            'state': 'open'
                        }
                        
                        self.results['ports'].append(port_info)
                        
        except Exception as e:
            log.warning(f"    ⚠️  Failed to parse nmap XML: {str(e)}")
    
    async def _basic_port_scan(self, target: str) -> None:
        """Basic port scanning fallback"""
        common_ports = [22, 25, 53, 80, 443, 8080, 8443]
        
        semaphore = asyncio.Semaphore(10)
        
        async def check_port(port: int) -> Optional[Dict]:
            async with semaphore:
                try:
                    # Use netcat for basic port check
                    process = await asyncio.create_subprocess_exec(
                        'nc', '-z', '-w', '3', target, str(port),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await process.communicate()
                    
                    if process.returncode == 0:
                        return {
                            'target': target,
                            'port': port,
                            'protocol': 'tcp',
                            'service': self._identify_service(port),
                            'version': '',
                            'state': 'open'
                        }
                except Exception:
                    pass
                return None
        
        tasks = [check_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict):
                self.results['ports'].append(result)
    
    def _identify_service(self, port: int) -> str:
        """Identify service by port number"""
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            3306: 'mysql', 5432: 'postgresql', 8080: 'http-alt',
            8443: 'https-alt', 9200: 'elasticsearch'
        }
        return service_map.get(port, 'unknown')
    
    async def _technology_fingerprinting(self) -> None:
        """Perform technology fingerprinting using WhatWeb"""
        log.info("  🛠️  Fingerprinting technologies with WhatWeb...")
        
        try:
            await self._check_budget("Technology fingerprinting")
            
            # Get web targets (HTTP/HTTPS services)
            web_targets = self._get_web_targets()
            
            for target in web_targets[:3]:  # Limit for budget
                await self._fingerprint_target(target)
            
            log.info(f"    ✅ Detected {len(self.results['technologies'])} technologies")
            self.budget_used += 1
            
        except Exception as e:
            log.error(f"    ❌ Technology fingerprinting failed: {str(e)}")
    
    def _get_web_targets(self) -> List[str]:
        """Get web targets from discovered services"""
        web_targets = []
        
        # Add main target
        web_targets.extend([
            f"http://{self.scope.target}",
            f"https://{self.scope.target}"
        ])
        
        # Add discovered web services
        for port_info in self.results['ports']:
            if port_info['service'] in ['http', 'https', 'http-alt', 'https-alt']:
                protocol = 'https' if 'https' in port_info['service'] else 'http'
                port = port_info['port']
                target = port_info['target']
                
                if port in [80, 443]:
                    web_targets.append(f"{protocol}://{target}")
                else:
                    web_targets.append(f"{protocol}://{target}:{port}")
        
        return list(set(web_targets))  # Remove duplicates
    
    async def _fingerprint_target(self, target: str) -> None:
        """Fingerprint a specific web target"""
        try:
            # Try WhatWeb first
            cmd = [
                'whatweb',
                '--color=never',
                '--no-errors',
                '--format=json',
                target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                await self._parse_whatweb_output(stdout.decode(), target)
            else:
                log.warning(f"    ⚠️  WhatWeb failed for {target}, using fallback")
                await self._basic_fingerprint(target)
                
        except FileNotFoundError:
            log.warning(f"    ⚠️  WhatWeb not found, using basic fingerprinting for {target}")
            await self._basic_fingerprint(target)
        except Exception as e:
            log.warning(f"    ⚠️  Fingerprinting failed for {target}: {str(e)}")
    
    async def _parse_whatweb_output(self, output: str, target: str) -> None:
        """Parse WhatWeb JSON output"""
        try:
            for line in output.strip().split('\n'):
                if line.strip():
                    data = json.loads(line)
                    
                    for plugin_name, plugin_data in data.get('plugins', {}).items():
                        if isinstance(plugin_data, dict):
                            tech_info = {
                                'target': target,
                                'name': plugin_name,
                                'category': self._categorize_technology(plugin_name),
                                'version': plugin_data.get('version', [''])[0] if plugin_data.get('version') else '',
                                'confidence': 'high',
                                'source': 'WhatWeb'
                            }
                            self.results['technologies'].append(tech_info)
                            
        except Exception as e:
            log.warning(f"    ⚠️  Failed to parse WhatWeb output: {str(e)}")
    
    async def _basic_fingerprint(self, target: str) -> None:
        """Basic technology fingerprinting fallback"""
        try:
            response = await self.http_client.get(target, follow_redirects=True)
            
            # Analyze headers
            server = response.headers.get('server', '')
            powered_by = response.headers.get('x-powered-by', '')
            
            if server:
                self.results['technologies'].append({
                    'target': target,
                    'name': server.split('/')[0],
                    'category': 'server',
                    'version': server.split('/')[1] if '/' in server else '',
                    'confidence': 'medium',
                    'source': 'HTTP Headers'
                })
            
            if powered_by:
                self.results['technologies'].append({
                    'target': target,
                    'name': powered_by,
                    'category': 'framework',
                    'version': '',
                    'confidence': 'medium',
                    'source': 'HTTP Headers'
                })
            
            # Basic content analysis
            content = response.text.lower()
            
            # Check for common frameworks
            frameworks = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Drupal': ['drupal', 'sites/default'],
                'Joomla': ['joomla', 'media/system'],
                'React': ['react', 'reactjs'],
                'Angular': ['angular', 'ng-app'],
                'Vue.js': ['vue.js', 'vuejs']
            }
            
            for framework, indicators in frameworks.items():
                if any(indicator in content for indicator in indicators):
                    self.results['technologies'].append({
                        'target': target,
                        'name': framework,
                        'category': 'framework',
                        'version': '',
                        'confidence': 'low',
                        'source': 'Content Analysis'
                    })
            
        except Exception as e:
            log.warning(f"    ⚠️  Basic fingerprinting failed for {target}: {str(e)}")
    
    def _categorize_technology(self, tech_name: str) -> str:
        """Categorize technology type"""
        tech_name_lower = tech_name.lower()
        
        if any(server in tech_name_lower for server in ['apache', 'nginx', 'iis', 'lighttpd']):
            return 'server'
        elif any(lang in tech_name_lower for lang in ['php', 'python', 'java', 'node']):
            return 'language'
        elif any(fw in tech_name_lower for fw in ['wordpress', 'drupal', 'joomla', 'django']):
            return 'cms'
        elif any(js in tech_name_lower for js in ['jquery', 'react', 'angular', 'vue']):
            return 'javascript'
        else:
            return 'other'
    
    async def _osint_collection(self) -> None:
        """Collect OSINT data from multiple sources"""
        log.info("  🕵️  Collecting OSINT data...")
        
        try:
            await self._check_budget("OSINT collection")
            
            # Collect from multiple sources concurrently
            tasks = [
                self._shodan_lookup(),
                self._censys_lookup(),
                self._certificate_transparency(),
                self._dns_records(),
            ]
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            log.info("    ✅ OSINT collection completed")
            self.budget_used += 3
            
        except Exception as e:
            log.error(f"    ❌ OSINT collection failed: {str(e)}")
    
    async def _shodan_lookup(self) -> None:
        """Lookup target information in Shodan"""
        if not self.shodan_client:
            return
        
        try:
            # Get IPs to lookup
            ips = list(self.results['ips'])
            
            for ip in ips[:3]:  # Limit API calls
                try:
                    # Run Shodan lookup in executor to avoid blocking
                    loop = asyncio.get_event_loop()
                    host_info = await loop.run_in_executor(
                        None, self.shodan_client.host, ip
                    )
                    
                    if not self.results['osint'].get('shodan'):
                        self.results['osint']['shodan'] = []
                    
                    self.results['osint']['shodan'].append({
                        'ip': ip,
                        'hostnames': host_info.get('hostnames', []),
                        'ports': host_info.get('ports', []),
                        'vulns': list(host_info.get('vulns', [])),
                        'org': host_info.get('org', ''),
                        'country': host_info.get('country_name', '')
                    })
                    
                except Exception as e:
                    log.debug(f"    Shodan lookup failed for {ip}: {str(e)}")
                    
        except Exception as e:
            log.warning(f"    ⚠️  Shodan OSINT failed: {str(e)}")
    
    async def _censys_lookup(self) -> None:
        """Lookup target information in Censys"""
        try:
            # Placeholder for Censys API integration
            # In production, implement actual Censys API calls
            log.debug("    Censys lookup placeholder")
            
        except Exception as e:
            log.warning(f"    ⚠️  Censys OSINT failed: {str(e)}")
    
    async def _certificate_transparency(self) -> None:
        """Query certificate transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.scope.target}&output=json"
            response = await self.http_client.get(url)
            
            if response.status_code == 200:
                ct_data = response.json()
                
                for cert in ct_data[:10]:  # Limit results
                    cert_info = {
                        'common_name': cert.get('common_name', ''),
                        'name_value': cert.get('name_value', ''),
                        'issuer_name': cert.get('issuer_name', ''),
                        'not_before': cert.get('not_before', ''),
                        'not_after': cert.get('not_after', '')
                    }
                    self.results['certificates'].append(cert_info)
                    
                    # Extract additional subdomains
                    if cert.get('name_value'):
                        domains = cert['name_value'].split('\n')
                        for domain in domains:
                            domain = domain.strip()
                            if self._is_in_scope(domain):
                                self.results['subdomains'].add(domain)
                
                if not self.results['osint'].get('certificates'):
                    self.results['osint']['certificates'] = len(self.results['certificates'])
                    
        except Exception as e:
            log.warning(f"    ⚠️  Certificate transparency lookup failed: {str(e)}")
    
    async def _dns_records(self) -> None:
        """Collect DNS record information"""
        try:
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
            dns_info = {}
            
            for record_type in record_types:
                try:
                    cmd = ['dig', '+short', self.scope.target, record_type]
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, _ = await process.communicate()
                    
                    if process.returncode == 0:
                        records = [r.strip() for r in stdout.decode().strip().split('\n') if r.strip()]
                        if records:
                            dns_info[record_type] = records
                            
                except Exception:
                    continue
            
            if dns_info:
                self.results['osint']['dns'] = dns_info
                
        except Exception as e:
            log.warning(f"    ⚠️  DNS record lookup failed: {str(e)}")
    
    def _is_in_scope(self, domain: str) -> bool:
        """Check if domain is in scope"""
        return domain.endswith(self.scope.target) or domain == self.scope.target
    
    async def _emit_subdomains(self) -> None:
        """Emit subdomain discovery event"""
        subdomain_list = list(self.results['subdomains'])
        await self.bus.emit("recon.subdomains", {
            'target': self.scope.target,
            'subdomains': subdomain_list,
            'count': len(subdomain_list),
            'timestamp': int(time.time())
        })
        log.info(f"    📡 Emitted {len(subdomain_list)} subdomains")
    
    async def _emit_ports(self) -> None:
        """Emit port scan results event"""
        await self.bus.emit("recon.ports", {
            'target': self.scope.target,
            'ports': self.results['ports'],
            'count': len(self.results['ports']),
            'timestamp': int(time.time())
        })
        log.info(f"    🔍 Emitted {len(self.results['ports'])} port results")
    
    async def _emit_technologies(self) -> None:
        """Emit technology detection event"""
        await self.bus.emit("recon.tech", {
            'target': self.scope.target,
            'technologies': self.results['technologies'],
            'count': len(self.results['technologies']),
            'timestamp': int(time.time())
        })
        log.info(f"    🛠️  Emitted {len(self.results['technologies'])} technologies")
    
    async def _emit_osint(self) -> None:
        """Emit OSINT collection event"""
        await self.bus.emit("recon.osint", {
            'target': self.scope.target,
            'osint': self.results['osint'],
            'certificates': len(self.results['certificates']),
            'ips': list(self.results['ips']),
            'timestamp': int(time.time())
        })
        log.info("    🕵️  Emitted OSINT data")
    
    def get_results(self) -> Dict[str, Any]:
        """Get reconnaissance results"""
        # Convert sets to lists for JSON serialization
        return {
            **self.results,
            'subdomains': list(self.results['subdomains']),
            'ips': list(self.results['ips'])
        }
