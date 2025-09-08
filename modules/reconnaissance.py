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

class Reconnaissance:
    def __init__(self, target: str, config: Optional[Dict] = None):
        self.target = target
        self.config = config or {}
        self.results = {
            'target': target,
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
            'timestamp': int(time.time())
        }

    def run_full_recon(self) -> Dict:
        """Execute comprehensive reconnaissance"""
        print(f"🔍 Starting next-gen web reconnaissance on {self.target}")
        
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
        
        # Zero-day hunting integration
        self.zero_day_surface_analysis()
        
        # Convert sets to lists for JSON serialization
        self.results['subdomains'] = list(self.results['subdomains'])
        self.results['emails'] = list(self.results['emails'])
        self.results['endpoints'] = list(self.results['endpoints'])
        
        print(f"✅ Next-gen reconnaissance completed for {self.target}")
        return self.results

    def subdomain_enumeration(self):
        """Advanced subdomain enumeration using multiple techniques"""
        print("  📡 Enumerating subdomains...")
        
        # DNS brute force with common subdomains
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'portal', 'support', 'secure', 'vpn',
            'cdn', 'static', 'assets', 'images', 'm', 'mobile', 'wap',
            'beta', 'alpha', 'demo', 'sandbox', 'help', 'docs', 'wiki'
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
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
                    pass  # DNS resolution failed

    def _check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists"""
        try:
            full_domain = f"{subdomain}.{self.target}"
            dns.resolver.resolve(full_domain, 'A')
            return True
        except:
            return False

    def port_scanning(self):
        """Scan for open ports and services"""
        print("  🔍 Scanning common ports...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                       1433, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200]
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._scan_port, port): port 
                for port in common_ports
            }
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        service = self._identify_service(port)
                        self.results['open_ports'].append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                except Exception:
                    pass

    def _scan_port(self, port: int) -> bool:
        """Check if port is open"""
        try:
            with socket.create_connection((self.target, port), timeout=3):
                return True
        except:
            return False

    def _identify_service(self, port: int) -> str:
        """Identify service running on port"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5984: 'CouchDB', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
        }
        return service_map.get(port, 'Unknown')

    def advanced_technology_detection(self):
        """Advanced web technology and framework detection"""
        print("  🛠️  Detecting modern web technologies...")
        
        try:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{self.target}"
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    
                    # Advanced header analysis
                    self._analyze_advanced_headers(response.headers)
                    
                    # Modern framework detection
                    self._detect_modern_frameworks(response.text, response.headers)
                    
                    # API framework detection
                    self._detect_api_frameworks(response.text, response.headers)
                    
                    # Security headers analysis
                    self._analyze_security_headers(response.headers)
                    
                    break
                    
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"    ⚠️  Advanced technology detection failed: {str(e)}")

    def _analyze_advanced_headers(self, headers: Dict):
        """Advanced HTTP header analysis for modern web technologies"""
        
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
                                'confidence': 'HIGH'
                            })
                else:
                    self.results['technologies'].append({
                        'type': 'Framework',
                        'name': indicators,
                        'source': f'HTTP Header: {header_name}',
                        'confidence': 'HIGH'
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
        """Analyze security-related headers"""
        
        security_headers = {
            'content-security-policy': 'CSP',
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer Policy',
            'permissions-policy': 'Permissions Policy'
        }
        
        security_analysis = {
            'present': [],
            'missing': [],
            'misconfigured': []
        }
        
        for header, name in security_headers.items():
            if header in headers:
                security_analysis['present'].append(name)
                # Check for common misconfigurations
                value = headers[header].lower()
                if header == 'x-frame-options' and value == 'allow':
                    security_analysis['misconfigured'].append(f"{name}: {value}")
            else:
                security_analysis['missing'].append(name)
        
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
        """Discover and analyze API endpoint"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            if response.status_code < 400:
                api_info = {
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'api_type': self._identify_api_type(response)
                }
                
                # Try to extract API version and endpoints
                if 'application/json' in api_info['content_type']:
                    try:
                        json_data = response.json()
                        api_info['endpoints'] = self._extract_api_endpoints(json_data)
                    except:
                        pass
                
                return api_info
        except:
            pass
        
        return None

    def _identify_api_type(self, response) -> str:
        """Identify API type from response"""
        content_type = response.headers.get('content-type', '').lower()
        content = response.text.lower()
        
        if 'graphql' in content or 'query' in content and 'mutation' in content:
            return 'GraphQL'
        elif 'swagger' in content or 'openapi' in content:
            return 'REST (OpenAPI)'
        elif 'wsdl' in content or 'soap' in content:
            return 'SOAP'
        elif 'application/json' in content_type:
            return 'REST JSON'
        elif 'application/xml' in content_type:
            return 'REST XML'
        else:
            return 'Unknown'

    def _extract_api_endpoints(self, json_data: Dict) -> List[str]:
        """Extract API endpoints from JSON response"""
        endpoints = []
        
        # Common patterns in API documentation
        if isinstance(json_data, dict):
            # OpenAPI/Swagger format
            if 'paths' in json_data:
                endpoints.extend(json_data['paths'].keys())
            
            # Custom endpoint listings
            for key in ['endpoints', 'routes', 'apis', 'services']:
                if key in json_data and isinstance(json_data[key], list):
                    endpoints.extend(json_data[key])
        
        return endpoints[:20]  # Limit to 20 endpoints

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
        """Discover GraphQL endpoints and schemas"""
        print("  📊 Discovering GraphQL endpoints...")
        
        graphql_paths = [
            '/graphql', '/api/graphql', '/v1/graphql', '/query',
            '/gql', '/api/gql', '/graphiql', '/graphql-explorer'
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
                    
                    response = requests.post(url, json=introspection_query, timeout=5)
                    
                    if response.status_code == 200 and 'data' in response.text:
                        schema_info = self._analyze_graphql_schema(response.text)
                        
                        self.results['graphql_endpoints'].append({
                            'url': url,
                            'introspection_enabled': True,
                            'schema_info': schema_info
                        })
                        
                except Exception:
                    continue

    def _analyze_graphql_schema(self, response_text: str) -> Dict:
        """Analyze GraphQL schema information"""
        try:
            response_data = json.loads(response_text)
            schema_data = response_data.get('data', {}).get('__schema', {})
            
            return {
                'query_type': schema_data.get('queryType', {}).get('name', ''),
                'mutation_type': schema_data.get('mutationType', {}).get('name', ''),
                'has_mutations': bool(schema_data.get('mutationType')),
                'has_subscriptions': bool(schema_data.get('subscriptionType'))
            }
        except:
            return {}

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

    def zero_day_surface_analysis(self):
        """Analyze attack surface for zero-day potential"""
        print("  🎯 Analyzing zero-day attack surface...")
        
        try:
            self.results['zero_day_surface'] = {
                'high_value_targets': [],
                'attack_vectors': [],
                'code_exposure': [],
                'novel_technologies': []
            }
            
            # Identify high-value targets for zero-day hunting
            high_value_indicators = [
                'admin', 'api', 'internal', 'dev', 'test',
                'staging', 'beta', 'upload', 'file'
            ]
            
            for endpoint in self.results['endpoints']:
                if any(indicator in endpoint.lower() for indicator in high_value_indicators):
                    self.results['zero_day_surface']['high_value_targets'].append({
                        'endpoint': endpoint,
                        'risk_level': 'HIGH',
                        'reason': 'High-value endpoint identified'
                    })
            
            # Analyze attack vectors
            for tech in self.results['technologies']:
                if tech.get('confidence') == 'HIGH':
                    self.results['zero_day_surface']['attack_vectors'].append({
                        'technology': tech['name'],
                        'type': tech['type'],
                        'attack_potential': 'MEDIUM'
                    })
            
            # Check for code exposure
            code_indicators = ['.git', '.svn', 'backup', '.bak', 'source']
            for endpoint in self.results['endpoints']:
                if any(indicator in endpoint.lower() for indicator in code_indicators):
                    self.results['zero_day_surface']['code_exposure'].append({
                        'endpoint': endpoint,
                        'exposure_type': 'Source Code',
                        'risk': 'CRITICAL'
                    })
            
            # Novel technology analysis
            novel_frameworks = []
            for framework in self.results['js_frameworks']:
                if framework.get('confidence') == 'HIGH' and 'novel' not in framework.get('evidence', []):
                    novel_frameworks.append(framework)
            
            self.results['zero_day_surface']['novel_technologies'] = novel_frameworks
            
        except Exception as e:
            print(f"    ⚠️  Zero-day surface analysis failed: {str(e)}")

    def generate_report(self) -> str:
        """Generate reconnaissance report"""
        report = f"""
DIVYASTRA Reconnaissance Report
Target: {self.target}
Timestamp: {self.results['timestamp']}

SUBDOMAINS DISCOVERED ({len(self.results['subdomains'])}):
{chr(10).join(f"  • {sub}" for sub in sorted(self.results['subdomains']))}

OPEN PORTS ({len(self.results['open_ports'])}):
{chr(10).join(f"  • {port['port']}/tcp ({port['service']})" for port in self.results['open_ports'])}

TECHNOLOGIES DETECTED ({len(self.results['technologies'])}):
{chr(10).join(f"  • {tech['name']} ({tech['type']})" for tech in self.results['technologies'])}

ENDPOINTS DISCOVERED ({len(self.results['endpoints'])}):
{chr(10).join(f"  • {endpoint}" for endpoint in sorted(self.results['endpoints']))}

CERTIFICATES ({len(self.results['certificates'])}):
{chr(10).join(f"  • {cert['common_name']}" for cert in self.results['certificates'])}
"""
        return report