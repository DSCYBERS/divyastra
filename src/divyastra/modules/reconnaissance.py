import asyncio
import requests
import dns.resolver
import ssl
import socket
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urljoin
import json
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

class Reconnaissance:
    def __init__(self, target: str, config: Optional[Dict] = None):
        self.target = self._sanitize_target(target)
        self.config = config or {}
        
        # Security: Add request session with proper configuration
        self.session = self._create_secure_session()
        
        # Rate limiting configuration
        self.max_workers = min(self.config.get('max_workers', 10), 20)  # Limit concurrent requests
        self.request_timeout = self.config.get('timeout', 10)
        self.max_retries = self.config.get('max_retries', 3)
        
        self.results = {
            'target': self.target,
            'subdomains': set(),
            'open_ports': [],
            'technologies': [],
            'emails': set(),
            'certificates': [],
            'endpoints': set(),
            'osint_data': {},
            'api_endpoints': [],
            'js_frameworks': [],
            'spa_technologies': [],
            'websockets': [],
            'graphql_endpoints': [],
            'microservices': [],
            'cloud_services': [],
            'security_headers': {},
            'vulnerabilities': [],  # Track potential security issues
            'timestamp': int(time.time())
        }

    def _sanitize_target(self, target: str) -> str:
        """Sanitize and validate target domain"""
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(target):
            raise ValueError(f"Invalid domain format: {target}")
        
        return target.lower().strip()
    
    def _create_secure_session(self) -> requests.Session:
        """Create a secure requests session with proper configuration"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Security headers
        session.headers.update({
            'User-Agent': 'DIVYASTRA Security Scanner/1.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
        return session

    def run_full_recon(self) -> Dict:
        """Execute comprehensive reconnaissance with error handling"""
        log.info(f"🔍 Starting next-gen web reconnaissance on {self.target}")
        
        try:
            # Traditional reconnaissance
            self.subdomain_enumeration()
            self.port_scanning()
            self.certificate_transparency()
            
            # Next-gen web reconnaissance
            self.advanced_technology_detection()
            self.api_discovery()
            self.spa_analysis()
            self.javascript_framework_detection()
            self.websocket_discovery()
            self.graphql_discovery()
            self.microservice_detection()
            self.cloud_service_detection()
            self.osint_gathering()
            self.endpoint_discovery()
            
            # Zero-day surface analysis
            self.zero_day_surface_analysis()
            
            # Security analysis
            self._analyze_security_posture()
            
            # Convert sets to lists for JSON serialization
            self.results['subdomains'] = list(self.results['subdomains'])
            self.results['emails'] = list(self.results['emails'])
            self.results['endpoints'] = list(self.results['endpoints'])
            
            log.info(f"✅ Next-gen reconnaissance completed for {self.target}")
            
        except Exception as e:
            log.error(f"❌ Reconnaissance failed: {str(e)}")
            self.results['error'] = str(e)
        
        finally:
            # Cleanup
            if hasattr(self, 'session'):
                self.session.close()
        
        return self.results

    def subdomain_enumeration(self):
        """Advanced subdomain enumeration with security fixes"""
        log.info("  📡 Enumerating subdomains...")
        
        # Security: Expanded subdomain list with security-focused subdomains
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'portal', 'support', 'secure', 'vpn',
            'cdn', 'static', 'assets', 'images', 'm', 'mobile', 'wap',
            'beta', 'alpha', 'demo', 'sandbox', 'help', 'docs', 'wiki',
            # Security-focused subdomains
            'internal', 'intranet', 'private', 'secret', 'hidden', 'backup',
            'old', 'legacy', 'archive', 'temp', 'tmp', 'debug', 'trace',
            'monitoring', 'metrics', 'health', 'status', 'grafana', 'kibana'
        ]
        
        # Rate limiting with semaphore
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def check_subdomain_async(subdomain):
            async with semaphore:
                try:
                    return await asyncio.get_event_loop().run_in_executor(
                        None, self._check_subdomain, subdomain
                    )
                except Exception as e:
                    log.debug(f"Subdomain check failed for {subdomain}: {e}")
                    return False
        
        # Use asyncio for better performance and rate limiting
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            tasks = [check_subdomain_async(sub) for sub in common_subs]
            results = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
            
            for sub, result in zip(common_subs, results):
                if result is True:
                    subdomain = f"{sub}.{self.target}"
                    self.results['subdomains'].add(subdomain)
                    
                    # Security check: Flag potentially sensitive subdomains
                    if sub in ['admin', 'internal', 'private', 'secret', 'debug']:
                        self.results['vulnerabilities'].append({
                            'type': 'Sensitive Subdomain Exposed',
                            'severity': 'HIGH',
                            'description': f"Potentially sensitive subdomain found: {subdomain}",
                            'recommendation': 'Review access controls for sensitive subdomains'
                        })
            
            loop.close()
            
        except Exception as e:
            log.error(f"Subdomain enumeration failed: {e}")
            # Fallback to synchronous method
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._check_subdomain, sub): sub 
                    for sub in common_subs
                }
                
                for future in as_completed(futures):
                    subdomain = futures[future]
                    try:
                        if future.result():
                            self.results['subdomains'].add(f"{subdomain}.{self.target}")
                    except Exception as e:
                        log.debug(f"Subdomain check failed: {e}")

    def _check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists with timeout and error handling"""
        try:
            full_domain = f"{subdomain}.{self.target}"
            
            # Set shorter timeout for DNS resolution
            dns.resolver.default_resolver.timeout = 3
            dns.resolver.default_resolver.lifetime = 3
            
            dns.resolver.resolve(full_domain, 'A')
            return True
            
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.Timeout:
            log.debug(f"DNS timeout for {subdomain}.{self.target}")
            return False
        except Exception as e:
            log.debug(f"DNS resolution failed for {subdomain}.{self.target}: {e}")
            return False

    def port_scanning(self):
        """Enhanced port scanning with security analysis"""
        log.info("  🔍 Scanning common ports...")
        
        # Extended port list including security-relevant ports
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200, 9300,
            # Security testing ports
            111, 512, 513, 514, 1099, 2049, 2121, 4444, 5555, 6666, 7777,
            8888, 9999, 10000, 27017, 27018, 27019, 50070
        ]
        
        # Rate limiting for port scanning
        with ThreadPoolExecutor(max_workers=min(self.max_workers, 50)) as executor:
            futures = {
                executor.submit(self._scan_port, port): port 
                for port in common_ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        service = self._identify_service(port)
                        port_info = {
                            'port': port,
                            'service': service,
                            'state': 'open'
                        }
                        self.results['open_ports'].append(port_info)
                        
                        # Security analysis for dangerous ports
                        if port in [21, 23, 135, 139, 445, 1433, 3389, 5432]:
                            self.results['vulnerabilities'].append({
                                'type': 'Potentially Dangerous Port Open',
                                'severity': 'MEDIUM',
                                'description': f"Port {port} ({service}) is open and may pose security risks",
                                'port': port,
                                'service': service,
                                'recommendation': 'Review if this service needs to be publicly accessible'
                            })
                            
                except Exception as e:
                    log.debug(f"Port scan failed for {port}: {e}")

    def _scan_port(self, port: int) -> bool:
        """Enhanced port scanning with proper timeout"""
        try:
            # Use smaller timeout for port scanning
            sock = socket.create_connection((self.target, port), timeout=2)
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            log.debug(f"Port scan error for {port}: {e}")
            return False

    def _identify_service(self, port: int) -> str:
        """Enhanced service identification"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            135: 'RPC', 139: 'NetBIOS-SSN', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 512: 'exec', 513: 'login',
            514: 'shell', 993: 'IMAPS', 995: 'POP3S',
            1099: 'RMI', 1433: 'MSSQL', 1521: 'Oracle',
            2049: 'NFS', 2121: 'FTP', 3306: 'MySQL', 3389: 'RDP',
            4444: 'Metasploit', 5432: 'PostgreSQL', 5555: 'HP Data Protector',
            5984: 'CouchDB', 6379: 'Redis', 6666: 'IRC', 7777: 'cbt',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
            9200: 'Elasticsearch', 9300: 'Elasticsearch', 9999: 'Telnet',
            10000: 'Webmin', 27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB',
            50070: 'Hadoop'
        }
        return service_map.get(port, 'Unknown')

    def advanced_technology_detection(self):
        """Enhanced technology detection with security analysis"""
        log.info("  🛠️  Detecting modern web technologies...")
        
        try:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{self.target}"
                    
                    # Use secure session with timeout
                    response = self.session.get(
                        url, 
                        timeout=self.request_timeout,
                        allow_redirects=True,
                        verify=False  # For security testing
                    )
                    
                    # Advanced header analysis
                    self._analyze_advanced_headers(response.headers, url)
                    
                    # Modern framework detection
                    self._detect_modern_frameworks(response.text, response.headers)
                    
                    # API framework detection
                    self._detect_api_frameworks(response.text, response.headers)
                    
                    # Security headers analysis
                    self._analyze_security_headers(response.headers)
                    
                    # Security vulnerability detection
                    self._detect_security_issues(response)
                    
                    break
                    
                except requests.exceptions.RequestException as e:
                    log.debug(f"Request failed for {scheme}://{self.target}: {e}")
                    continue
                    
        except Exception as e:
            log.error(f"Advanced technology detection failed: {str(e)}")

    def _detect_security_issues(self, response):
        """Detect potential security issues from HTTP response"""
        
        # Check for information disclosure in headers
        sensitive_headers = [
            'x-powered-by', 'server', 'x-aspnet-version', 
            'x-generator', 'x-drupal-cache'
        ]
        
        for header in sensitive_headers:
            if header in response.headers:
                self.results['vulnerabilities'].append({
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'description': f"Sensitive header exposed: {header}",
                    'value': response.headers[header],
                    'recommendation': f'Remove or obfuscate {header} header'
                })
        
        # Check for error pages that might leak information
        error_indicators = [
            'stack trace', 'exception', 'error', 'debug',
            'mysql_connect', 'postgresql', 'oracle error',
            'microsoft jet database', 'odbc', 'asp.net'
        ]
        
        response_lower = response.text.lower()
        for indicator in error_indicators:
            if indicator in response_lower:
                self.results['vulnerabilities'].append({
                    'type': 'Information Disclosure',
                    'severity': 'MEDIUM',
                    'description': f"Potential error information leaked: {indicator}",
                    'recommendation': 'Implement proper error handling'
                })
                break

    def _analyze_advanced_headers(self, headers: Dict, url: str):
        """Enhanced header analysis with security checks"""
        
        # Modern framework indicators
        advanced_indicators = {
            'x-next-js': 'Next.js',
            'x-nuxt-js': 'Nuxt.js',
            'x-gatsby': 'Gatsby',
            'x-svelte': 'SvelteKit',
            'x-remix': 'Remix',
            'server': {
                'vercel': 'Vercel',
                'netlify': 'Netlify',
                'cloudflare': 'Cloudflare',
                'fastly': 'Fastly',
                'amazon': 'AWS',
                'google': 'Google Cloud'
            },
            'x-powered-by': {
                'express': 'Express.js',
                'koa': 'Koa.js',
                'fastify': 'Fastify',
                'nest': 'NestJS',
                'django': 'Django',
                'flask': 'Flask',
                'spring': 'Spring Boot',
                'asp.net': 'ASP.NET Core'
            }
        }
        
        for header_name, indicators in advanced_indicators.items():
            header_value = headers.get(header_name, '').lower()
            if header_value:
                if isinstance(indicators, dict):
                    for keyword, tech in indicators.items():
                        if keyword in header_value:
                            self.results['technologies'].append({
                                'type': 'Backend Framework',
                                'name': tech,
                                'source': f'HTTP Header: {header_name}',
                                'confidence': 'HIGH',
                                'url': url
                            })
                else:
                    self.results['technologies'].append({
                        'type': 'Framework',
                        'name': indicators,
                        'source': f'HTTP Header: {header_name}',
                        'confidence': 'HIGH',
                        'url': url
                    })

    def _detect_modern_frameworks(self, html: str, headers: Dict):
        """Detect modern JavaScript frameworks and libraries"""
        
        framework_signatures = {
            # React ecosystem
            'React': {
                'patterns': ['react', 'reactdom', '_reactinternalfiber', 'react-dom'],
                'dom_indicators': ['data-react', 'data-reactroot'],
                'js_patterns': ['React.createElement', 'React.Component']
            },
            'Next.js': {
                'patterns': ['_next/static', '__NEXT_DATA__', 'next/head'],
                'dom_indicators': ['__next'],
                'js_patterns': ['__NEXT_LOADED_PAGES__']
            },
            # Angular ecosystem  
            'Angular': {
                'patterns': ['ng-app', 'ng-controller', 'angular.min.js'],
                'dom_indicators': ['ng-version', 'ng-app', 'data-ng'],
                'js_patterns': ['angular.module', 'ng-app']
            },
            'AngularJS': {
                'patterns': ['angularjs', 'angular.js'],
                'dom_indicators': ['ng-app', 'ng-controller'],
                'js_patterns': ['angular.module']
            },
            # Vue ecosystem
            'Vue.js': {
                'patterns': ['vue.js', 'vue.min.js', 'vuejs'],
                'dom_indicators': ['v-if', 'v-for', 'v-model', 'data-v-'],
                'js_patterns': ['new Vue', 'Vue.component']
            },
            'Nuxt.js': {
                'patterns': ['_nuxt/', '__NUXT__'],
                'dom_indicators': ['__nuxt', 'nuxt-'],
                'js_patterns': ['window.__NUXT__']
            },
            # Other modern frameworks
            'Svelte': {
                'patterns': ['svelte', '_app/immutable'],
                'dom_indicators': ['svelte-'],
                'js_patterns': ['SvelteComponent']
            },
            'Gatsby': {
                'patterns': ['gatsby-', '___gatsby'],
                'dom_indicators': ['gatsby-focus-wrapper'],
                'js_patterns': ['___loader']
            }
        }
        
        html_lower = html.lower()
        
        for framework, signatures in framework_signatures.items():
            confidence = 0
            evidence = []
            
            # Check HTML patterns
            for pattern in signatures['patterns']:
                if pattern in html_lower:
                    confidence += 30
                    evidence.append(f"HTML pattern: {pattern}")
            
            # Check DOM indicators
            for indicator in signatures['dom_indicators']:
                if indicator in html_lower:
                    confidence += 40
                    evidence.append(f"DOM indicator: {indicator}")
            
            # Check JavaScript patterns
            for js_pattern in signatures['js_patterns']:
                if js_pattern.lower() in html_lower:
                    confidence += 50
                    evidence.append(f"JS pattern: {js_pattern}")
            
            if confidence >= 40:
                confidence_level = 'HIGH' if confidence >= 80 else 'MEDIUM'
                
                self.results['js_frameworks'].append({
                    'name': framework,
                    'confidence': confidence_level,
                    'evidence': evidence,
                    'score': confidence
                })

    def _detect_api_frameworks(self, html: str, headers: Dict):
        """Detect API frameworks and technologies"""
        
        api_indicators = {
            'GraphQL': ['graphql', '/graphql', 'query', 'mutation'],
            'REST API': ['api/', '/api/', 'rest', 'restful'],
            'WebSocket': ['websocket', 'ws://', 'wss://'],
            'gRPC': ['grpc', 'proto'],
            'JSON-RPC': ['jsonrpc', 'json-rpc'],
            'SOAP': ['soap', 'wsdl', 'xmlns:soap']
        }
        
        html_lower = html.lower()
        
        for api_type, patterns in api_indicators.items():
            if any(pattern in html_lower for pattern in patterns):
                self.results['technologies'].append({
                    'type': 'API Technology',
                    'name': api_type,
                    'source': 'HTML Analysis',
                    'confidence': 'MEDIUM'
                })

    def _analyze_security_headers(self, headers: Dict):
        """Enhanced security header analysis"""
        
        security_headers = {
            'content-security-policy': 'CSP',
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer Policy',
            'permissions-policy': 'Permissions Policy',
            'feature-policy': 'Feature Policy'
        }
        
        security_analysis = {
            'present': [],
            'missing': [],
            'misconfigured': []
        }
        
        for header, name in security_headers.items():
            if header in headers:
                security_analysis['present'].append(name)
                
                # Check for misconfigurations
                value = headers[header].lower()
                
                if header == 'x-frame-options' and 'allow' in value:
                    security_analysis['misconfigured'].append(f"{name}: {value}")
                    self.results['vulnerabilities'].append({
                        'type': 'Security Misconfiguration',
                        'severity': 'MEDIUM',
                        'description': f'Insecure X-Frame-Options: {value}',
                        'recommendation': 'Use DENY or SAMEORIGIN instead of ALLOW'
                    })
                
                elif header == 'x-xss-protection' and '0' in value:
                    security_analysis['misconfigured'].append(f"{name}: disabled")
                    self.results['vulnerabilities'].append({
                        'type': 'Security Misconfiguration',
                        'severity': 'LOW',
                        'description': 'XSS Protection is disabled',
                        'recommendation': 'Enable XSS protection with "1; mode=block"'
                    })
                    
            else:
                security_analysis['missing'].append(name)
        
        # Flag missing critical security headers
        critical_missing = [h for h in ['HSTS', 'CSP', 'X-Frame-Options'] 
                          if h in security_analysis['missing']]
        
        if critical_missing:
            self.results['vulnerabilities'].append({
                'type': 'Missing Security Headers',
                'severity': 'MEDIUM',
                'description': f"Critical security headers missing: {', '.join(critical_missing)}",
                'recommendation': 'Implement missing security headers'
            })
        
        self.results['security_headers'] = security_analysis

    def api_discovery(self):
        """Discover API endpoints and documentation"""
        print("  🔌 Discovering API endpoints...")
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2',
            '/graphql', '/api/graphql', '/query',
            '/rest', '/restapi', '/api/rest',
            '/swagger', '/api-docs', '/docs/api',
            '/openapi.json', '/swagger.json', '/api.json'
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            for base_url in base_urls:
                futures = {
                    executor.submit(self._discover_api_endpoint, f"{base_url}{path}"): path
                    for path in api_paths
                }
                
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.results['api_endpoints'].append(result)
                    except Exception:
                        pass

    def _discover_api_endpoint(self, url: str) -> Optional[Dict]:
        """Enhanced API endpoint discovery with security checks"""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=True)
            
            if response.status_code < 400:
                api_info = {
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'api_type': self._identify_api_type(response)
                }
                
                # Security check: Look for exposed API documentation
                if response.status_code == 200 and any(keyword in response.text.lower() 
                    for keyword in ['swagger', 'openapi', 'api documentation', 'graphql playground']):
                    
                    self.results['vulnerabilities'].append({
                        'type': 'API Documentation Exposed',
                        'severity': 'LOW',
                        'description': f'API documentation publicly accessible at {url}',
                        'recommendation': 'Review if API documentation should be publicly accessible'
                    })
                
                # Try to extract API version and endpoints
                if 'application/json' in api_info['content_type']:
                    try:
                        json_data = response.json()
                        api_info['endpoints'] = self._extract_api_endpoints(json_data)
                        
                        # Security check: Look for sensitive data in API responses
                        sensitive_keys = ['password', 'secret', 'token', 'key', 'private']
                        json_str = str(json_data).lower()
                        
                        for sensitive_key in sensitive_keys:
                            if sensitive_key in json_str:
                                self.results['vulnerabilities'].append({
                                    'type': 'Sensitive Data Exposure',
                                    'severity': 'HIGH',
                                    'description': f'Potentially sensitive data in API response: {sensitive_key}',
                                    'url': url,
                                    'recommendation': 'Review API response for sensitive data leaks'
                                })
                                break
                                
                    except json.JSONDecodeError:
                        pass
                
                return api_info
                
        except Exception as e:
            log.debug(f"API endpoint discovery failed for {url}: {e}")
        
        return None

    def spa_analysis(self):
        """Analyze Single Page Application characteristics"""
        print("  📱 Analyzing SPA characteristics...")
        
        try:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{self.target}"
                    response = requests.get(url, timeout=10)
                    
                    spa_indicators = self._detect_spa_patterns(response.text)
                    if spa_indicators:
                        self.results['spa_technologies'] = spa_indicators
                    break
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"    ⚠️  SPA analysis failed: {str(e)}")

    def _detect_spa_patterns(self, html: str) -> List[Dict]:
        """Detect SPA patterns and characteristics"""
        
        spa_patterns = {
            'Client-Side Routing': {
                'patterns': ['history.pushstate', 'react-router', 'vue-router', '@angular/router'],
                'dom_patterns': ['router-outlet', 'router-view']
            },
            'State Management': {
                'patterns': ['redux', 'vuex', 'mobx', 'zustand', 'pinia'],
                'dom_patterns': ['redux-store', 'vuex-store']
            },
            'Module Bundling': {
                'patterns': ['webpack', 'rollup', 'parcel', 'vite'],
                'dom_patterns': ['webpack_require', '__webpack_modules__']
            },
            'Build Tools': {
                'patterns': ['babel', 'typescript', 'esbuild'],
                'dom_patterns': ['__webpack_exports__']
            }
        }
        
        detected_patterns = []
        html_lower = html.lower()
        
        for pattern_type, indicators in spa_patterns.items():
            evidence = []
            
            for pattern in indicators['patterns']:
                if pattern in html_lower:
                    evidence.append(pattern)
            
            for dom_pattern in indicators['dom_patterns']:
                if dom_pattern in html_lower:
                    evidence.append(dom_pattern)
            
            if evidence:
                detected_patterns.append({
                    'type': pattern_type,
                    'evidence': evidence,
                    'confidence': 'HIGH' if len(evidence) > 1 else 'MEDIUM'
                })
        
        return detected_patterns

    def javascript_framework_detection(self):
        """Detailed JavaScript framework and library detection"""
        print("  🔧 Detecting JavaScript frameworks...")
        
        try:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{self.target}"
                    response = requests.get(url, timeout=10)
                    
                    # Extract and analyze JavaScript files
                    js_files = self._extract_js_files(response.text, url)
                    self._analyze_js_files(js_files)
                    
                    break
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"    ⚠️  JavaScript framework detection failed: {str(e)}")

    def _extract_js_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_files = []
        
        # Find script tags with src attributes
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.findall(script_pattern, html, re.IGNORECASE)
        
        for match in matches:
            if match.startswith('http'):
                js_files.append(match)
            elif match.startswith('/'):
                js_files.append(urljoin(base_url, match))
            else:
                js_files.append(urljoin(base_url + '/', match))
        
        return js_files[:10]  # Limit to 10 JS files

    def _analyze_js_files(self, js_files: List[str]):
        """Analyze JavaScript files for framework signatures"""
        
        for js_url in js_files:
            try:
                response = requests.get(js_url, timeout=5)
                if response.status_code == 200:
                    js_content = response.text[:10000]  # Analyze first 10KB
                    
                    # Framework detection patterns
                    framework_patterns = {
                        'React': ['React.createElement', 'ReactDOM.render', '_reactInternalFiber'],
                        'Angular': ['angular.module', 'ng.core', '@angular/core'],
                        'Vue.js': ['Vue.component', 'new Vue', 'vue.runtime'],
                        'jQuery': ['jQuery', '$', 'jquery'],
                        'Lodash': ['lodash', '_.map', '_.filter'],
                        'D3.js': ['d3.select', 'd3.scale', 'd3.svg'],
                        'Three.js': ['THREE.Scene', 'THREE.Camera']
                    }
                    
                    for framework, patterns in framework_patterns.items():
                        if any(pattern in js_content for pattern in patterns):
                            # Check if already detected
                            existing = next((f for f in self.results['js_frameworks'] if f['name'] == framework), None)
                            if not existing:
                                self.results['js_frameworks'].append({
                                    'name': framework,
                                    'confidence': 'HIGH',
                                    'source': f'JavaScript file: {js_url}',
                                    'evidence': [p for p in patterns if p in js_content]
                                })
                            
            except Exception:
                continue

    def websocket_discovery(self):
        """Discover WebSocket endpoints"""
        print("  🔌 Discovering WebSocket endpoints...")
        
        websocket_paths = [
            '/ws', '/websocket', '/socket', '/realtime',
            '/live', '/stream', '/events', '/notifications'
        ]
        
        for scheme in ['wss', 'ws']:
            base_url = f"{scheme}://{self.target}"
            
            for path in websocket_paths:
                try:
                    # Simple WebSocket connection test (simplified)
                    ws_url = f"{base_url}{path}"
                    
                    # In production, use websocket library
                    # For now, just check if the endpoint exists via HTTP
                    http_scheme = 'https' if scheme == 'wss' else 'http'
                    check_url = f"{http_scheme}://{self.target}{path}"
                    
                    response = requests.head(check_url, timeout=5)
                    if 'upgrade' in response.headers.get('connection', '').lower():
                        self.results['websockets'].append({
                            'url': ws_url,
                            'status': 'potential_websocket'
                        })
                        
                except Exception:
                    continue

    def graphql_discovery(self):
        """Enhanced GraphQL discovery with security testing"""
        log.info("  📊 Discovering GraphQL endpoints...")
        
        graphql_paths = [
            '/graphql', '/api/graphql', '/v1/graphql', '/query',
            '/gql', '/api/gql', '/graphiql', '/graphql-explorer',
            '/console', '/playground'  # Additional GraphQL interfaces
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        for base_url in base_urls:
            for path in graphql_paths:
                try:
                    url = f"{base_url}{path}"
                    
                    # Test with introspection query
                    introspection_query = {
                        "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                    }
                    
                    response = self.session.post(
                        url, 
                        json=introspection_query, 
                        timeout=self.request_timeout
                    )
                    
                    if response.status_code == 200 and 'data' in response.text:
                        schema_info = self._analyze_graphql_schema(response.text)
                        
                        # Security check: GraphQL introspection enabled
                        if schema_info:
                            self.results['vulnerabilities'].append({
                                'type': 'GraphQL Introspection Enabled',
                                'severity': 'MEDIUM',
                                'description': f'GraphQL introspection is enabled at {url}',
                                'url': url,
                                'recommendation': 'Disable introspection in production'
                            })
                        
                        self.results['graphql_endpoints'].append({
                            'url': url,
                            'introspection_enabled': True,
                            'schema_info': schema_info
                        })
                    
                    # Test for GraphQL IDE interfaces
                    elif response.status_code == 200 and any(ide in response.text.lower() 
                        for ide in ['graphiql', 'playground', 'graphql console']):
                        
                        self.results['vulnerabilities'].append({
                            'type': 'GraphQL IDE Exposed',
                            'severity': 'LOW',
                            'description': f'GraphQL IDE interface accessible at {url}',
                            'url': url,
                            'recommendation': 'Remove GraphQL IDE from production'
                        })
                        
                except Exception as e:
                    log.debug(f"GraphQL discovery failed for {url}: {e}")

    def microservice_detection(self):
        """Detect microservice architecture patterns"""
        print("  🏗️  Detecting microservice patterns...")
        
        microservice_indicators = [
            '/health', '/actuator', '/metrics', '/status',
            '/api/health', '/api/status', '/healthcheck',
            '/service/', '/services/', '/micro/', '/ms/'
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        for base_url in base_urls:
            for indicator in microservice_indicators:
                try:
                    url = f"{base_url}{indicator}"
                    response = requests.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        service_info = self._analyze_service_endpoint(response)
                        if service_info:
                            self.results['microservices'].append({
                                'url': url,
                                'type': service_info['type'],
                                'info': service_info['data']
                            })
                            
                except Exception:
                    continue

    def _analyze_service_endpoint(self, response) -> Optional[Dict]:
        """Analyze service endpoint response"""
        try:
            content_type = response.headers.get('content-type', '')
            
            if 'application/json' in content_type:
                data = response.json()
                
                # Spring Boot Actuator
                if 'status' in data and 'diskSpace' in str(data):
                    return {'type': 'Spring Boot Actuator', 'data': data}
                
                # Generic health check
                elif 'status' in data or 'health' in data:
                    return {'type': 'Health Check', 'data': data}
                
                # Service discovery
                elif 'services' in data or 'instances' in data:
                    return {'type': 'Service Discovery', 'data': data}
            
            return None
            
        except Exception:
            return None

    def cloud_service_detection(self):
        """Detect cloud service providers and services"""
        print("  ☁️  Detecting cloud services...")
        
        try:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{self.target}"
                    response = requests.get(url, timeout=10)
                    
                    cloud_info = self._analyze_cloud_indicators(response.headers, response.text)
                    if cloud_info:
                        self.results['cloud_services'] = cloud_info
                    
                    break
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"    ⚠️  Cloud service detection failed: {str(e)}")

    def _analyze_cloud_indicators(self, headers: Dict, content: str) -> List[Dict]:
        """Analyze cloud service indicators"""
        
        cloud_indicators = {
            'AWS': {
                'headers': ['x-amz-', 'x-amazon-', 'server.*amazon'],
                'content': ['amazonaws.com', 'aws-', 'cloudfront']
            },
            'Google Cloud': {
                'headers': ['x-goog-', 'server.*gws'],
                'content': ['googleapis.com', 'gstatic.com', 'googleusercontent.com']
            },
            'Microsoft Azure': {
                'headers': ['x-ms-', 'server.*azure'],
                'content': ['azurewebsites.net', 'azure.com', 'microsoftonline.com']
            },
            'Cloudflare': {
                'headers': ['cf-ray', 'server.*cloudflare'],
                'content': ['cloudflare', 'cf-ray']
            },
            'Vercel': {
                'headers': ['x-vercel-', 'server.*vercel'],
                'content': ['vercel.app', '_vercel']
            },
            'Netlify': {
                'headers': ['server.*netlify'],
                'content': ['netlify.app', 'netlify.com']
            }
        }
        
        detected_services = []
        headers_str = ' '.join([f"{k}:{v}" for k, v in headers.items()]).lower()
        content_lower = content.lower()
        
        for provider, indicators in cloud_indicators.items():
            evidence = []
            confidence = 0
            
            # Check headers
            for header_pattern in indicators['headers']:
                if re.search(header_pattern, headers_str):
                    evidence.append(f"Header: {header_pattern}")
                    confidence += 40
            
            # Check content
            for content_pattern in indicators['content']:
                if content_pattern in content_lower:
                    evidence.append(f"Content: {content_pattern}")
                    confidence += 30
            
            if confidence >= 30:
                detected_services.append({
                    'provider': provider,
                    'confidence': 'HIGH' if confidence >= 60 else 'MEDIUM',
                    'evidence': evidence
                })
        
        return detected_services

    def certificate_transparency(self):
        """Query certificate transparency logs"""
        print("  🔐 Checking certificate transparency logs...")
        
        try:
            # This is a simplified version - in production you'd use CT APIs
            # like crt.sh, Censys, or Certificate Transparency APIs
            ct_url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = requests.get(ct_url, timeout=15)
            
            if response.status_code == 200:
                ct_data = response.json()
                for cert in ct_data[:10]:  # Limit to first 10 entries
                    self.results['certificates'].append({
                        'common_name': cert.get('common_name', ''),
                        'name_value': cert.get('name_value', ''),
                        'issuer_name': cert.get('issuer_name', ''),
                        'not_before': cert.get('not_before', ''),
                        'not_after': cert.get('not_after', '')
                    })
                    
                    # Extract additional subdomains from certificates
                    if cert.get('name_value'):
                        domains = cert['name_value'].split('\n')
                        for domain in domains:
                            domain = domain.strip()
                            if domain.endswith(f".{self.target}"):
                                self.results['subdomains'].add(domain)
                                
        except Exception as e:
            print(f"    ⚠️  Certificate transparency check failed: {str(e)}")

    def osint_gathering(self):
        """Gather open source intelligence"""
        print("  🕵️  Gathering OSINT data...")
        
        self.results['osint_data'] = {
            'social_media': self._search_social_media(),
            'breach_data': self._check_breach_databases(),
            'company_info': self._gather_company_info(),
            'employee_emails': self._discover_emails()
        }

    def _search_social_media(self) -> List[Dict]:
        """Search for social media presence (placeholder)"""
        # In production, integrate with social media APIs
        return []

    def _check_breach_databases(self) -> List[Dict]:
        """Check known breach databases (placeholder)"""
        # In production, integrate with HaveIBeenPwned or similar APIs
        return []

    def _gather_company_info(self) -> Dict:
        """Gather company information (placeholder)"""
        return {}

    def _discover_emails(self) -> Set[str]:
        """Discover email addresses associated with domain"""
        emails = set()
        
        # Common email patterns
        common_emails = [
            f"admin@{self.target}",
            f"info@{self.target}",
            f"contact@{self.target}",
            f"support@{self.target}",
            f"sales@{self.target}",
            f"noreply@{self.target}"
        ]
        
        for email in common_emails:
            # In production, you'd validate these emails
            emails.add(email)
            
        return emails

    def endpoint_discovery(self):
        """Discover web endpoints and directories"""
        print("  📂 Discovering endpoints...")
        
        common_paths = [
            '/admin', '/api', '/login', '/dashboard', '/config',
            '/backup', '/test', '/dev', '/staging', '/uploads',
            '/assets', '/static', '/js', '/css', '/images',
            '/.git', '/.svn', '/robots.txt', '/sitemap.xml',
            '/.well-known', '/api/v1', '/api/v2', '/graphql',
            '/swagger', '/docs', '/health', '/status'
        ]
        
        base_urls = [f"https://{self.target}", f"http://{self.target}"]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            for base_url in base_urls:
                futures = {
                    executor.submit(self._check_endpoint, f"{base_url}{path}"): path
                    for path in common_paths
                }
                
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        if future.result():
                            self.results['endpoints'].add(f"{base_url}{path}")
                    except Exception:
                        pass

    def _check_endpoint(self, url: str) -> bool:
        """Check if endpoint exists"""
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            return response.status_code < 400
        except:
            return False

    def generate_report(self) -> str:
        """Generate enhanced reconnaissance report with security analysis"""
        vuln_summary = {}
        for vuln in self.results.get('vulnerabilities', []):
            severity = vuln['severity']
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1
        
        security_posture = self.results.get('security_posture', {})
        
        report = f"""
DIVYASTRA Enhanced Reconnaissance Report
Target: {self.target}
Timestamp: {self.results['timestamp']}
Security Score: {security_posture.get('score', 'N/A')} ({security_posture.get('grade', 'N/A')})

SECURITY SUMMARY:
  Critical Vulnerabilities: {vuln_summary.get('CRITICAL', 0)}
  High Vulnerabilities: {vuln_summary.get('HIGH', 0)}
  Medium Vulnerabilities: {vuln_summary.get('MEDIUM', 0)}
  Low Vulnerabilities: {vuln_summary.get('LOW', 0)}

SUBDOMAINS DISCOVERED ({len(self.results['subdomains'])}):
{chr(10).join(f"  • {sub}" for sub in sorted(self.results['subdomains']))}

OPEN PORTS ({len(self.results['open_ports'])}):
{chr(10).join(f"  • {port['port']}/tcp ({port['service']})" for port in self.results['open_ports'])}

TECHNOLOGIES DETECTED ({len(self.results['technologies'])}):
{chr(10).join(f"  • {tech['name']} ({tech['type']})" for tech in self.results['technologies'])}

SECURITY VULNERABILITIES:
{chr(10).join(f"  • [{vuln['severity']}] {vuln['type']}: {vuln['description']}" for vuln in self.results.get('vulnerabilities', [])[:10])}

SECURITY RECOMMENDATIONS:
{chr(10).join(f"  • {rec}" for rec in security_posture.get('recommendations', []))}

ENDPOINTS DISCOVERED ({len(self.results['endpoints'])}):
{chr(10).join(f"  • {endpoint}" for endpoint in sorted(self.results['endpoints']))}

CERTIFICATES ({len(self.results['certificates'])}):
{chr(10).join(f"  • {cert['common_name']}" for cert in self.results['certificates'])}
"""
        return report
    
    def _analyze_graphql_schema(self, response_text: str) -> Optional[Dict]:
        """Analyze GraphQL schema for security issues"""
        try:
            data = json.loads(response_text)
            schema_info = {
                'types_count': 0,
                'queries_available': [],
                'mutations_available': [],
                'sensitive_fields': [],
                'complexity_score': 0
            }
            
            if 'data' in data and '__schema' in data['data']:
                schema = data['data']['__schema']
                
                # Count types
                if 'types' in schema:
                    schema_info['types_count'] = len(schema['types'])
                    
                    # Look for sensitive fields
                    sensitive_keywords = ['password', 'secret', 'token', 'key', 'private', 'admin', 'internal']
                    
                    for type_def in schema['types']:
                        if 'fields' in type_def and type_def['fields']:
                            for field in type_def['fields']:
                                field_name = field.get('name', '').lower()
                                if any(keyword in field_name for keyword in sensitive_keywords):
                                    schema_info['sensitive_fields'].append({
                                        'type': type_def.get('name'),
                                        'field': field.get('name'),
                                        'field_type': field.get('type', {}).get('name')
                                    })
                
                # Extract query and mutation info
                if 'queryType' in schema:
                    schema_info['queries_available'].append(schema['queryType'].get('name'))
                
                if 'mutationType' in schema:
                    schema_info['mutations_available'].append(schema['mutationType'].get('name'))
                
                # Calculate complexity score
                schema_info['complexity_score'] = min(schema_info['types_count'] * 2, 100)
                
                # Security check: Flag sensitive fields exposure
                if schema_info['sensitive_fields']:
                    self.results['vulnerabilities'].append({
                        'type': 'GraphQL Sensitive Field Exposure',
                        'severity': 'HIGH',
                        'description': f'GraphQL schema exposes {len(schema_info["sensitive_fields"])} sensitive fields',
                        'fields': schema_info['sensitive_fields'][:5],  # First 5
                        'recommendation': 'Remove sensitive fields from public schema or implement field-level authorization'
                    })
            
            return schema_info
            
        except (json.JSONDecodeError, KeyError) as e:
            log.debug(f"Failed to parse GraphQL schema: {e}")
            return None

    def zero_day_surface_analysis(self):
        """Enhanced zero-day attack surface analysis with comprehensive security checks"""
        log.info("  🎯 Analyzing zero-day attack surface...")
        
        try:
            self.results['zero_day_surface'] = {
                'high_value_targets': [],
                'attack_vectors': [],
                'code_exposure': [],
                'novel_technologies': [],
                'security_weaknesses': [],
                'injection_points': [],
                'authentication_weaknesses': [],
                'session_vulnerabilities': [],
                'business_logic_flaws': []
            }
            
            # Critical security analysis
            self._analyze_injection_attack_surface()
            self._analyze_authentication_attack_surface() 
            self._analyze_session_attack_surface()
            self._analyze_business_logic_attack_surface()
            
            # Identify high-value targets for zero-day hunting
            high_value_indicators = [
                'admin', 'api', 'internal', 'dev', 'test',
                'staging', 'beta', 'upload', 'file', 'console',
                'dashboard', 'management', 'control', 'config',
                'backup', 'database', 'db', 'sql', 'mongodb'
            ]
            
            for endpoint in self.results['endpoints']:
                endpoint_lower = endpoint.lower()
                for indicator in high_value_indicators:
                    if indicator in endpoint_lower:
                        risk_level = self._calculate_endpoint_risk(indicator, endpoint)
                        
                        self.results['zero_day_surface']['high_value_targets'].append({
                            'endpoint': endpoint,
                            'risk_level': risk_level,
                            'reason': f'High-value endpoint: {indicator}',
                            'indicator': indicator,
                            'attack_probability': self._calculate_attack_probability(indicator)
                        })
                        
                        # Add specific vulnerability checks for high-value endpoints
                        self._check_endpoint_specific_vulns(endpoint, indicator)
                        break
            
            # Enhanced attack vector analysis
            for tech in self.results['technologies']:
                if tech.get('confidence') == 'HIGH':
                    attack_potential = self._assess_attack_potential(tech['name'])
                    cve_risk = self._check_known_cves(tech['name'])
                    
                    if attack_potential != 'LOW' or cve_risk > 0:
                        self.results['zero_day_surface']['attack_vectors'].append({
                            'technology': tech['name'],
                            'type': tech['type'],
                            'attack_potential': attack_potential,
                            'known_cves': cve_risk,
                            'source': tech.get('source', 'Unknown'),
                            'mitigation_priority': self._get_mitigation_priority(attack_potential, cve_risk)
                        })
            
            # Enhanced code exposure analysis
            code_indicators = [
                ('.git', 'CRITICAL', 'Git Repository'),
                ('.svn', 'CRITICAL', 'SVN Repository'), 
                ('backup', 'HIGH', 'Backup Files'),
                ('.bak', 'HIGH', 'Backup Files'),
                ('source', 'HIGH', 'Source Code'),
                ('.env', 'CRITICAL', 'Environment Config'),
                ('config', 'HIGH', 'Configuration'),
                ('.sql', 'CRITICAL', 'Database Dump'),
                ('.dump', 'CRITICAL', 'Database Dump'),
                ('debug', 'MEDIUM', 'Debug Information'),
                ('.log', 'MEDIUM', 'Log Files'),
                ('.old', 'MEDIUM', 'Old Files'),
                ('temp', 'MEDIUM', 'Temporary Files'),
                ('.tmp', 'MEDIUM', 'Temporary Files')
            ]
            
            for endpoint in self.results['endpoints']:
                endpoint_lower = endpoint.lower()
                for indicator, risk, description in code_indicators:
                    if indicator in endpoint_lower:
                        self.results['zero_day_surface']['code_exposure'].append({
                            'endpoint': endpoint,
                            'exposure_type': indicator,
                            'risk': risk,
                            'description': description,
                            'exploitation_difficulty': self._assess_exploitation_difficulty(indicator),
                            'data_sensitivity': self._assess_data_sensitivity(indicator)
                        })
            
            # Novel technology zero-day analysis
            novel_frameworks = []
            for framework in self.results['js_frameworks']:
                if framework.get('confidence') == 'HIGH':
                    novelty_score = self._calculate_novelty_score(framework['name'])
                    security_maturity = self._assess_security_maturity(framework['name'])
                    
                    if novelty_score > 60 or security_maturity < 50:
                        novel_frameworks.append({
                            **framework,
                            'novelty_score': novelty_score,
                            'security_maturity': security_maturity,
                            'zero_day_potential': self._calculate_zero_day_potential(novelty_score, security_maturity),
                            'research_priority': self._get_research_priority(novelty_score, security_maturity)
                        })
            
            self.results['zero_day_surface']['novel_technologies'] = novel_frameworks
            
            # Aggregate comprehensive security weaknesses
            self.results['zero_day_surface']['security_weaknesses'] = self._aggregate_security_weaknesses()
            
        except Exception as e:
            log.error(f"Zero-day surface analysis failed: {str(e)}")

    def _analyze_injection_attack_surface(self):
        """Analyze injection attack surface"""
        injection_points = []
        
        # Check API endpoints for injection vulnerabilities
        for api_endpoint in self.results.get('api_endpoints', []):
            url = api_endpoint.get('url', '')
            
            # Identify potential injection points
            if '?' in url or '/api/' in url:
                injection_points.append({
                    'type': 'API Parameter Injection',
                    'endpoint': url,
                    'risk': 'HIGH',
                    'vectors': ['SQL', 'NoSQL', 'LDAP', 'Command', 'XSS'],
                    'testing_priority': 'CRITICAL'
                })
        
        # Check GraphQL for injection risks
        for graphql_endpoint in self.results.get('graphql_endpoints', []):
            injection_points.append({
                'type': 'GraphQL Injection',
                'endpoint': graphql_endpoint.get('url', ''),
                'risk': 'HIGH',
                'vectors': ['Query Injection', 'Schema Injection'],
                'testing_priority': 'HIGH'
            })
        
        self.results['zero_day_surface']['injection_points'] = injection_points
    
    def _analyze_authentication_attack_surface(self):
        """Analyze authentication attack surface"""
        auth_weaknesses = []
        
        # Check for authentication endpoints
        auth_indicators = ['/login', '/auth', '/oauth', '/sso', '/jwt']
        
        for endpoint in self.results['endpoints']:
            if any(indicator in endpoint.lower() for indicator in auth_indicators):
                auth_weaknesses.append({
                    'type': 'Authentication Endpoint',
                    'endpoint': endpoint,
                    'potential_attacks': [
                        'Brute Force', 'Credential Stuffing', 
                        'Token Manipulation', 'Session Fixation'
                    ],
                    'testing_priority': 'HIGH'
                })
        
        # Check for JWT usage
        for tech in self.results['technologies']:
            if 'jwt' in tech['name'].lower() or 'json web token' in tech['name'].lower():
                auth_weaknesses.append({
                    'type': 'JWT Implementation',
                    'technology': tech['name'],
                    'potential_attacks': [
                        'Algorithm Confusion', 'Key Confusion',
                        'Token Manipulation', 'None Algorithm'
                    ],
                    'testing_priority': 'CRITICAL'
                })
        
        self.results['zero_day_surface']['authentication_weaknesses'] = auth_weaknesses
    
    def _analyze_session_attack_surface(self):
        """Analyze session management attack surface"""
        session_vulns = []
        
        # Check for session-related technologies
        session_indicators = ['session', 'cookie', 'redis', 'memcached']
        
        for tech in self.results['technologies']:
            tech_name_lower = tech['name'].lower()
            if any(indicator in tech_name_lower for indicator in session_indicators):
                session_vulns.append({
                    'type': 'Session Management Technology',
                    'technology': tech['name'],
                    'potential_attacks': [
                        'Session Fixation', 'Session Hijacking',
                        'Cross-Site Request Forgery', 'Session Prediction'
                    ],
                    'testing_priority': 'MEDIUM'
                })
        
        self.results['zero_day_surface']['session_vulnerabilities'] = session_vulns
    
    def _analyze_business_logic_attack_surface(self):
        """Analyze business logic attack surface"""
        business_logic_flaws = []
        
        # Check for business-critical endpoints
        business_indicators = [
            ('/payment', 'Financial Transaction', 'CRITICAL'),
            ('/transfer', 'Money Transfer', 'CRITICAL'),
            ('/order', 'Order Processing', 'HIGH'),
            ('/checkout', 'Purchase Flow', 'HIGH'),
            ('/cart', 'Shopping Cart', 'MEDIUM'),
            ('/pricing', 'Price Calculation', 'HIGH'),
            ('/discount', 'Discount Application', 'MEDIUM')
        ]
        
        for endpoint in self.results['endpoints']:
            for indicator, description, risk in business_indicators:
                if indicator in endpoint.lower():
                    business_logic_flaws.append({
                        'type': 'Business Logic Endpoint',
                        'endpoint': endpoint,
                        'description': description,
                        'risk': risk,
                        'potential_attacks': [
                            'Race Conditions', 'Price Manipulation',
                            'Workflow Bypass', 'Logic Bomb'
                        ],
                        'testing_priority': risk
                    })
        
        self.results['zero_day_surface']['business_logic_flaws'] = business_logic_flaws

    def _calculate_endpoint_risk(self, indicator: str, endpoint: str) -> str:
        """Calculate risk level for endpoint"""
        critical_indicators = ['admin', 'config', 'database', 'backup']
        high_indicators = ['api', 'upload', 'file', 'internal']
        
        if indicator in critical_indicators:
            return 'CRITICAL'
        elif indicator in high_indicators:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _calculate_attack_probability(self, indicator: str) -> int:
        """Calculate attack probability (0-100)"""
        probabilities = {
            'admin': 95, 'config': 90, 'database': 85, 'backup': 80,
            'api': 75, 'upload': 70, 'file': 65, 'internal': 60
        }
        return probabilities.get(indicator, 50)
    
    def _check_endpoint_specific_vulns(self, endpoint: str, indicator: str):
        """Check for endpoint-specific vulnerabilities"""
        endpoint_lower = endpoint.lower()
        
        # File upload vulnerabilities
        if 'upload' in indicator:
            self.results['vulnerabilities'].append({
                'type': 'Potential File Upload Vulnerability',
                'severity': 'HIGH',
                'description': f'File upload endpoint detected: {endpoint}',
                'recommendation': 'Implement file type validation, size limits, and malware scanning',
                'attack_vectors': ['Malicious File Upload', 'Path Traversal', 'Web Shell']
            })
        
        # Database access vulnerabilities  
        elif indicator in ['database', 'db', 'sql']:
            self.results['vulnerabilities'].append({
                'type': 'Database Access Endpoint',
                'severity': 'CRITICAL',
                'description': f'Database access endpoint exposed: {endpoint}',
                'recommendation': 'Restrict database endpoint access and implement authentication',
                'attack_vectors': ['SQL Injection', 'Data Exfiltration', 'Schema Enumeration']
            })
    
    def _assess_attack_potential(self, technology: str) -> str:
        """Assess attack potential of a technology"""
        high_risk_techs = [
            'struts', 'drupal', 'wordpress', 'joomla',
            'jenkins', 'apache', 'tomcat', 'spring'
        ]
        
        medium_risk_techs = [
            'react', 'angular', 'vue', 'node',
            'express', 'django', 'flask', 'laravel'
        ]
        
        tech_lower = technology.lower()
        
        if any(tech in tech_lower for tech in high_risk_techs):
            return 'HIGH'
        elif any(tech in tech_lower for tech in medium_risk_techs):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _check_known_cves(self, technology: str) -> int:
        """Check for known CVEs (simplified - in production use CVE database)"""
        # Simplified CVE risk scoring
        high_risk_techs = {
            'apache struts': 25, 'log4j': 20, 'spring': 15,
            'drupal': 18, 'wordpress': 12, 'joomla': 10,
            'jenkins': 15, 'tomcat': 12, 'nginx': 8
        }
        
        tech_lower = technology.lower()
        for risk_tech, score in high_risk_techs.items():
            if risk_tech in tech_lower:
                return score
        
        return 0
    
    def _get_mitigation_priority(self, attack_potential: str, cve_risk: int) -> str:
        """Get mitigation priority based on risk factors"""
        if attack_potential == 'HIGH' and cve_risk > 15:
            return 'CRITICAL'
        elif attack_potential == 'HIGH' or cve_risk > 10:
            return 'HIGH'
        elif attack_potential == 'MEDIUM' or cve_risk > 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_exploitation_difficulty(self, indicator: str) -> str:
        """Assess exploitation difficulty"""
        easy_exploits = ['.git', '.env', '.sql', 'backup']
        medium_exploits = ['config', 'debug', '.log']
        
        if indicator in easy_exploits:
            return 'EASY'
        elif indicator in medium_exploits:
            return 'MEDIUM'
        else:
            return 'HARD'
    
    def _assess_data_sensitivity(self, indicator: str) -> str:
        """Assess data sensitivity level"""
        critical_data = ['.git', '.env', '.sql', 'backup']
        sensitive_data = ['config', '.log', 'debug']
        
        if indicator in critical_data:
            return 'CRITICAL'
        elif indicator in sensitive_data:
            return 'SENSITIVE'
        else:
            return 'PUBLIC'
    
    def _calculate_novelty_score(self, framework: str) -> int:
        """Calculate novelty score for frameworks (higher = more novel/less tested)"""
        mature_frameworks = ['jquery', 'bootstrap', 'react', 'angular', 'vue']
        emerging_frameworks = ['svelte', 'solid', 'qwik', 'fresh', 'astro']
        
        framework_lower = framework.lower()
        
        if any(mature in framework_lower for mature in mature_frameworks):
            return 30  # Well-tested, lower novelty
        elif any(emerging in framework_lower for emerging in emerging_frameworks):
            return 85  # Emerging, higher novelty
        else:
            return 60  # Unknown/moderate novelty
    
    def _assess_security_maturity(self, framework: str) -> int:
        """Assess security maturity of framework (0-100)"""
        mature_frameworks = {
            'react': 85, 'angular': 80, 'vue': 75, 'jquery': 90,
            'bootstrap': 85, 'express': 70, 'django': 85, 'flask': 75
        }
        
        emerging_frameworks = {
            'svelte': 40, 'solid': 30, 'qwik': 25, 'fresh': 35,
            'astro': 45, 'remix': 50, 'nextjs': 70
        }
        
        framework_lower = framework.lower()
        
        for mature, score in mature_frameworks.items():
            if mature in framework_lower:
                return score
                
        for emerging, score in emerging_frameworks.items():
            if emerging in framework_lower:
                return score
        
        return 60  # Default moderate maturity
    
    def _calculate_zero_day_potential(self, novelty_score: int, security_maturity: int) -> str:
        """Calculate zero-day potential"""
        combined_score = novelty_score + (100 - security_maturity)
        
        if combined_score > 120:
            return 'VERY HIGH'
        elif combined_score > 100:
            return 'HIGH'
        elif combined_score > 80:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_research_priority(self, novelty_score: int, security_maturity: int) -> str:
        """Get research priority for zero-day hunting"""
        if novelty_score > 80 and security_maturity < 50:
            return 'CRITICAL'
        elif novelty_score > 60 or security_maturity < 60:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _aggregate_security_weaknesses(self) -> List[Dict]:
        """Aggregate all discovered security weaknesses"""
        weaknesses = []
        
        # High-value targets
        critical_targets = [t for t in self.results['zero_day_surface']['high_value_targets'] 
                          if t['risk_level'] == 'CRITICAL']
        if critical_targets:
            weaknesses.append({
                'category': 'Critical Endpoints Exposed',
                'count': len(critical_targets),
                'risk': 'CRITICAL',
                'description': 'Critical administrative or internal endpoints are accessible'
            })
        
        # Code exposure
        critical_exposure = [e for e in self.results['zero_day_surface']['code_exposure'] 
                           if e['risk'] == 'CRITICAL']
        if critical_exposure:
            weaknesses.append({
                'category': 'Source Code Exposure',
                'count': len(critical_exposure),
                'risk': 'CRITICAL',
                'description': 'Source code or configuration files may be exposed'
            })
        
        # Security vulnerabilities
        high_vulns = [v for v in self.results['vulnerabilities'] 
                     if v['severity'] in ['CRITICAL', 'HIGH']]
        if high_vulns:
            weaknesses.append({
                'category': 'Security Vulnerabilities',
                'count': len(high_vulns),
                'risk': 'HIGH',
                'description': 'Multiple security vulnerabilities detected'
            })
        
        return weaknesses