import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

from divyastra.agents.web_recon import WebReconAgent
from divyastra.core.event_bus import EventBus
from divyastra.core.scope import Scope

class TestWebReconAgent:
    
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock(spec=EventBus)
        bus.emit = AsyncMock()
        return bus
    
    @pytest.fixture
    def mock_scope(self):
        scope = MagicMock(spec=Scope)
        scope.target = "example.com"
        return scope
    
    @pytest.fixture
    def agent(self, mock_bus, mock_scope):
        return WebReconAgent(mock_bus, mock_scope, budget=100)
    
    @pytest.mark.asyncio
    async def test_init(self, mock_bus, mock_scope):
        """Test agent initialization"""
        agent = WebReconAgent(mock_bus, mock_scope, budget=50)
        
        assert agent.bus == mock_bus
        assert agent.scope == mock_scope
        assert agent.budget == 50
        assert agent.results['target'] == "example.com"
        assert agent.budget_used == 0
    
    @pytest.mark.asyncio
    async def test_check_budget_success(self, agent):
        """Test budget check when within limits"""
        agent.budget_used = 50
        agent.budget = 100
        
        # Should not raise exception
        await agent._check_budget("test operation")
    
    @pytest.mark.asyncio
    async def test_check_budget_exceeded(self, agent):
        """Test budget check when exceeded"""
        agent.budget_used = 100
        agent.budget = 50
        
        with pytest.raises(RuntimeError, match="Budget exceeded"):
            await agent._check_budget("test operation")
    
    @pytest.mark.asyncio
    @patch('asyncio.create_subprocess_exec')
    async def test_subdomain_enumeration_success(self, mock_subprocess, agent):
        """Test successful subdomain enumeration with subfinder"""
        # Mock subprocess
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (
            b"www.example.com\napi.example.com\nmail.example.com\n",
            b""
        )
        mock_subprocess.return_value = mock_process
        
        await agent._subdomain_enumeration()
        
        assert "www.example.com" in agent.results['subdomains']
        assert "api.example.com" in agent.results['subdomains']
        assert "mail.example.com" in agent.results['subdomains']
        assert agent.budget_used == 1
    
    @pytest.mark.asyncio
    @patch('asyncio.create_subprocess_exec')
    async def test_subdomain_enumeration_fallback(self, mock_subprocess, agent):
        """Test fallback subdomain enumeration when subfinder fails"""
        # Mock subfinder failure
        mock_subprocess.side_effect = FileNotFoundError()
        
        # Mock nslookup success for www subdomain
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"Address: 1.2.3.4\n", b"")
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            await agent._subdomain_enumeration()
        
        # Should have found at least some subdomains via fallback
        assert len(agent.results['subdomains']) > 0
    
    @pytest.mark.asyncio
    @patch('asyncio.create_subprocess_exec')
    async def test_port_scanning_success(self, mock_subprocess, agent):
        """Test successful port scanning with nmap"""
        # Mock nmap XML output
        nmap_xml = '''<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="1.2.3.4" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" version="2.4.41"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>'''
        
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (nmap_xml.encode(), b"")
        mock_subprocess.return_value = mock_process
        
        await agent._port_scanning()
        
        assert len(agent.results['ports']) >= 2
        assert "1.2.3.4" in agent.results['ips']
        assert any(p['port'] == 80 for p in agent.results['ports'])
        assert any(p['port'] == 443 for p in agent.results['ports'])
    
    @pytest.mark.asyncio
    @patch('asyncio.create_subprocess_exec')
    async def test_technology_fingerprinting_success(self, mock_subprocess, agent):
        """Test successful technology fingerprinting with WhatWeb"""
        # Setup ports for web targets
        agent.results['ports'] = [
            {'target': 'example.com', 'port': 80, 'service': 'http'},
            {'target': 'example.com', 'port': 443, 'service': 'https'}
        ]
        
        # Mock WhatWeb JSON output
        whatweb_output = json.dumps({
            "target": "https://example.com",
            "plugins": {
                "Apache": {"version": ["2.4.41"]},
                "PHP": {"version": ["7.4"]},
                "WordPress": {}
            }
        })
        
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (whatweb_output.encode(), b"")
        mock_subprocess.return_value = mock_process
        
        await agent._technology_fingerprinting()
        
        assert len(agent.results['technologies']) >= 3
        tech_names = [t['name'] for t in agent.results['technologies']]
        assert "Apache" in tech_names
        assert "PHP" in tech_names
        assert "WordPress" in tech_names
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_basic_fingerprint_fallback(self, mock_http_client, agent):
        """Test basic fingerprinting fallback"""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.headers = {
            'server': 'nginx/1.18.0',
            'x-powered-by': 'PHP/7.4.3'
        }
        mock_response.text = '<html><script src="jquery.min.js"></script></html>'
        
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_http_client.return_value = mock_client
        agent.http_client = mock_client
        
        await agent._basic_fingerprint("https://example.com")
        
        assert len(agent.results['technologies']) >= 2
        tech_names = [t['name'] for t in agent.results['technologies']]
        assert "nginx" in tech_names
        assert "PHP/7.4.3" in tech_names
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_certificate_transparency(self, mock_http_client, agent):
        """Test certificate transparency lookup"""
        # Mock crt.sh response
        ct_response = [
            {
                "common_name": "*.example.com",
                "name_value": "*.example.com\nexample.com\nwww.example.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2023-01-01T00:00:00",
                "not_after": "2023-12-31T23:59:59"
            }
        ]
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ct_response
        
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_http_client.return_value = mock_client
        agent.http_client = mock_client
        
        await agent._certificate_transparency()
        
        assert len(agent.results['certificates']) == 1
        assert "*.example.com" in agent.results['certificates'][0]['common_name']
        assert "www.example.com" in agent.results['subdomains']
    
    @pytest.mark.asyncio
    async def test_emit_subdomains(self, agent):
        """Test subdomain emission"""
        agent.results['subdomains'] = {"www.example.com", "api.example.com"}
        
        await agent._emit_subdomains()
        
        agent.bus.emit.assert_called_once()
        call_args = agent.bus.emit.call_args
        assert call_args[0][0] == "recon.subdomains"
        assert call_args[0][1]['count'] == 2
        assert "www.example.com" in call_args[0][1]['subdomains']
    
    @pytest.mark.asyncio
    async def test_emit_ports(self, agent):
        """Test port emission"""
        agent.results['ports'] = [
            {'port': 80, 'service': 'http'},
            {'port': 443, 'service': 'https'}
        ]
        
        await agent._emit_ports()
        
        agent.bus.emit.assert_called_once()
        call_args = agent.bus.emit.call_args
        assert call_args[0][0] == "recon.ports"
        assert call_args[0][1]['count'] == 2
    
    @pytest.mark.asyncio
    async def test_emit_technologies(self, agent):
        """Test technology emission"""
        agent.results['technologies'] = [
            {'name': 'Apache', 'category': 'server'},
            {'name': 'PHP', 'category': 'language'}
        ]
        
        await agent._emit_technologies()
        
        agent.bus.emit.assert_called_once()
        call_args = agent.bus.emit.call_args
        assert call_args[0][0] == "recon.tech"
        assert call_args[0][1]['count'] == 2
    
    @pytest.mark.asyncio
    async def test_emit_osint(self, agent):
        """Test OSINT emission"""
        agent.results['osint'] = {'certificates': 5}
        agent.results['certificates'] = ['cert1', 'cert2']
        agent.results['ips'] = {'1.2.3.4', '5.6.7.8'}
        
        await agent._emit_osint()
        
        agent.bus.emit.assert_called_once()
        call_args = agent.bus.emit.call_args
        assert call_args[0][0] == "recon.osint"
        assert call_args[0][1]['certificates'] == 2
        assert len(call_args[0][1]['ips']) == 2
    
    def test_is_in_scope(self, agent):
        """Test scope checking"""
        assert agent._is_in_scope("example.com") is True
        assert agent._is_in_scope("www.example.com") is True
        assert agent._is_in_scope("api.example.com") is True
        assert agent._is_in_scope("evil.com") is False
        assert agent._is_in_scope("notexample.com") is False
    
    def test_identify_service(self, agent):
        """Test service identification by port"""
        assert agent._identify_service(80) == "http"
        assert agent._identify_service(443) == "https"
        assert agent._identify_service(22) == "ssh"
        assert agent._identify_service(9999) == "unknown"
    
    def test_categorize_technology(self, agent):
        """Test technology categorization"""
        assert agent._categorize_technology("Apache") == "server"
        assert agent._categorize_technology("nginx") == "server"
        assert agent._categorize_technology("PHP") == "language"
        assert agent._categorize_technology("WordPress") == "cms"
        assert agent._categorize_technology("jQuery") == "javascript"
        assert agent._categorize_technology("Unknown") == "other"
    
    def test_get_results(self, agent):
        """Test results retrieval"""
        agent.results['subdomains'] = {"www.example.com"}
        agent.results['ips'] = {"1.2.3.4"}
        
        results = agent.get_results()
        
        assert isinstance(results['subdomains'], list)
        assert isinstance(results['ips'], list)
        assert "www.example.com" in results['subdomains']
        assert "1.2.3.4" in results['ips']
    
    @pytest.mark.asyncio
    @patch.dict('os.environ', {'SHODAN_API_KEY': 'test_key'})
    async def test_init_shodan_success(self, agent):
        """Test successful Shodan client initialization"""
        with patch('divyastra.agents.web_recon.Shodan') as mock_shodan:
            await agent._init_shodan()
            mock_shodan.assert_called_once_with('test_key')
            assert agent.shodan_client is not None
    
    @pytest.mark.asyncio
    async def test_init_shodan_no_key(self, agent):
        """Test Shodan client initialization without API key"""
        with patch.dict('os.environ', {}, clear=True):
            await agent._init_shodan()
            assert agent.shodan_client is None
    
    def test_get_web_targets(self, agent):
        """Test web target extraction"""
        agent.results['ports'] = [
            {'target': 'example.com', 'port': 80, 'service': 'http'},
            {'target': 'api.example.com', 'port': 443, 'service': 'https'},
            {'target': 'mail.example.com', 'port': 25, 'service': 'smtp'}
        ]
        
        targets = agent._get_web_targets()
        
        assert "http://example.com" in targets
        assert "https://example.com" in targets
        assert "http://example.com" in targets
        assert "https://api.example.com" in targets
        # SMTP should not be included
        assert not any('mail.example.com' in t for t in targets if 'smtp' in t)

if __name__ == "__main__":
    pytest.main([__file__])
