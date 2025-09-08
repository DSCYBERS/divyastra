"""
DIVYASTRA CLI Interface
Command-line interface for the DIVYASTRA penetration testing suite
"""

import sys
import asyncio
import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from .. import get_banner, get_version_info, __version__
from ..modules.reconnaissance import Reconnaissance
from ..core.config import Config
from ..core.logger import setup_logger
from ..agents.zero_day_hunter import ZeroDayHunterAgent
from ..core.event_bus import EventBus
from ..core.scope import Scope

logger = setup_logger(__name__)

class DivyastraCLI:
    """Main CLI interface for DIVYASTRA"""
    
    def __init__(self):
        self.config = Config()
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command line argument parser"""
        parser = argparse.ArgumentParser(
            prog='divyastra',
            description='DIVYASTRA - Next-Generation AI-Powered Web Penetration Testing Suite',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
Examples:
  # Basic reconnaissance
  divyastra recon --target example.com
  
  # Comprehensive next-gen assessment
  divyastra web --target https://app.example.com --mode nextgen
  
  # API security testing
  divyastra api --target https://api.example.com --rest --graphql
  
  # Zero-day discovery
  divyastra zero-day --target example.com --ai-enhanced
  
  # Business logic testing
  divyastra business-logic --target bank.com --race-conditions
  
Repository: https://github.com/DSCYBERS/divyastra
Documentation: https://docs.dscybers.org/divyastra
Support: https://discord.gg/dscybers-security
"""
        )
        
        # Global options
        parser.add_argument(
            '--version', '-v',
            action='version',
            version=f'DIVYASTRA v{__version__}'
        )
        
        parser.add_argument(
            '--config', '-c',
            type=str,
            help='Configuration file path'
        )
        
        parser.add_argument(
            '--output', '-o',
            type=str,
            help='Output directory for reports'
        )
        
        parser.add_argument(
            '--format',
            choices=['json', 'html', 'pdf', 'markdown'],
            default='json',
            help='Output format for reports'
        )
        
        parser.add_argument(
            '--verbose', '-V',
            action='store_true',
            help='Enable verbose logging'
        )
        
        parser.add_argument(
            '--banner',
            action='store_true',
            help='Show DIVYASTRA banner'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands',
            metavar='COMMAND'
        )
        
        # Reconnaissance command
        self._add_recon_parser(subparsers)
        
        # Web security testing command
        self._add_web_parser(subparsers)
        
        # API security testing command
        self._add_api_parser(subparsers)
        
        # Zero-day discovery command
        self._add_zero_day_parser(subparsers)
        
        # Business logic testing command
        self._add_business_logic_parser(subparsers)
        
        # Configuration management
        self._add_config_parser(subparsers)
        
        # Demo command
        self._add_demo_parser(subparsers)
        
        return parser
    
    def _add_recon_parser(self, subparsers):
        """Add reconnaissance command parser"""
        recon_parser = subparsers.add_parser(
            'recon',
            help='Reconnaissance and information gathering',
            description='Perform comprehensive reconnaissance on target'
        )
        
        recon_parser.add_argument(
            '--target', '-t',
            required=True,
            help='Target domain or URL'
        )
        
        recon_parser.add_argument(
            '--modules', '-m',
            help='Comma-separated list of modules to run',
            default='all'
        )
        
        recon_parser.add_argument(
            '--workers',
            type=int,
            default=10,
            help='Number of concurrent workers'
        )
        
        recon_parser.add_argument(
            '--timeout',
            type=int,
            default=10,
            help='Request timeout in seconds'
        )
        
        recon_parser.add_argument(
            '--deep',
            action='store_true',
            help='Enable deep reconnaissance'
        )
    
    def _add_web_parser(self, subparsers):
        """Add web security testing parser"""
        web_parser = subparsers.add_parser(
            'web',
            help='Next-generation web application security testing',
            description='Comprehensive web application security assessment'
        )
        
        web_parser.add_argument(
            '--target', '-t',
            required=True,
            help='Target web application URL'
        )
        
        web_parser.add_argument(
            '--mode',
            choices=['basic', 'standard', 'comprehensive', 'nextgen'],
            default='standard',
            help='Testing mode'
        )
        
        web_parser.add_argument(
            '--framework',
            choices=['react', 'angular', 'vue', 'svelte', 'auto'],
            default='auto',
            help='Target framework for specialized testing'
        )
        
        web_parser.add_argument(
            '--spa-analysis',
            action='store_true',
            help='Enable SPA deep analysis'
        )
        
        web_parser.add_argument(
            '--api-security',
            action='store_true',
            help='Enable API security testing'
        )
        
        web_parser.add_argument(
            '--graphql-testing',
            action='store_true',
            help='Enable GraphQL security testing'
        )
        
        web_parser.add_argument(
            '--business-logic',
            action='store_true',
            help='Enable business logic testing'
        )
        
        web_parser.add_argument(
            '--ai-enhanced',
            action='store_true',
            help='Enable AI-enhanced testing'
        )
    
    def _add_api_parser(self, subparsers):
        """Add API security testing parser"""
        api_parser = subparsers.add_parser(
            'api',
            help='API security testing',
            description='Comprehensive API security assessment'
        )
        
        api_parser.add_argument(
            '--target', '-t',
            required=True,
            help='Target API URL'
        )
        
        api_parser.add_argument(
            '--rest',
            action='store_true',
            help='Test REST APIs'
        )
        
        api_parser.add_argument(
            '--graphql',
            action='store_true',
            help='Test GraphQL APIs'
        )
        
        api_parser.add_argument(
            '--websocket',
            action='store_true',
            help='Test WebSocket connections'
        )
        
        api_parser.add_argument(
            '--bola-testing',
            action='store_true',
            help='Test for BOLA vulnerabilities'
        )
        
        api_parser.add_argument(
            '--rate-limit-bypass',
            action='store_true',
            help='Test rate limiting bypass'
        )
        
        api_parser.add_argument(
            '--cors-analysis',
            action='store_true',
            help='Analyze CORS configuration'
        )
    
    def _add_zero_day_parser(self, subparsers):
        """Add zero-day discovery parser"""
        zd_parser = subparsers.add_parser(
            'zero-day',
            help='AI-powered zero-day vulnerability discovery',
            description='Advanced zero-day vulnerability hunting'
        )
        
        zd_parser.add_argument(
            '--target', '-t',
            required=True,
            help='Target for zero-day hunting'
        )
        
        zd_parser.add_argument(
            '--static-analysis',
            action='store_true',
            help='Enable static code analysis'
        )
        
        zd_parser.add_argument(
            '--dynamic-analysis',
            action='store_true',
            help='Enable dynamic behavioral analysis'
        )
        
        zd_parser.add_argument(
            '--intelligent-fuzzing',
            action='store_true',
            help='Enable AI-powered fuzzing'
        )
        
        zd_parser.add_argument(
            '--pattern-mining',
            action='store_true',
            help='Enable pattern mining'
        )
        
        zd_parser.add_argument(
            '--poc-generation',
            action='store_true',
            help='Enable PoC generation'
        )
        
        zd_parser.add_argument(
            '--ai-confidence-threshold',
            type=int,
            default=80,
            help='AI confidence threshold (0-100)'
        )
        
        zd_parser.add_argument(
            '--budget',
            type=int,
            default=1000,
            help='Computational budget for analysis'
        )
    
    def _add_business_logic_parser(self, subparsers):
        """Add business logic testing parser"""
        bl_parser = subparsers.add_parser(
            'business-logic',
            help='Business logic vulnerability testing',
            description='Advanced business logic vulnerability detection'
        )
        
        bl_parser.add_argument(
            '--target', '-t',
            required=True,
            help='Target application'
        )
        
        bl_parser.add_argument(
            '--race-conditions',
            action='store_true',
            help='Test for race conditions'
        )
        
        bl_parser.add_argument(
            '--workflow-manipulation',
            action='store_true',
            help='Test workflow manipulation'
        )
        
        bl_parser.add_argument(
            '--privilege-escalation',
            action='store_true',
            help='Test privilege escalation'
        )
        
        bl_parser.add_argument(
            '--financial-logic',
            action='store_true',
            help='Test financial logic flaws'
        )
        
        bl_parser.add_argument(
            '--session-management',
            action='store_true',
            help='Test session management'
        )
    
    def _add_config_parser(self, subparsers):
        """Add configuration management parser"""
        config_parser = subparsers.add_parser(
            'config',
            help='Configuration management',
            description='Manage DIVYASTRA configuration'
        )
        
        config_subparsers = config_parser.add_subparsers(
            dest='config_action',
            help='Configuration actions'
        )
        
        # Initialize configuration
        init_parser = config_subparsers.add_parser(
            'init',
            help='Initialize DIVYASTRA configuration'
        )
        
        init_parser.add_argument(
            '--nextgen',
            action='store_true',
            help='Initialize with next-gen features'
        )
        
        # Set configuration values
        set_parser = config_subparsers.add_parser(
            'set',
            help='Set configuration values'
        )
        
        set_parser.add_argument(
            'key',
            help='Configuration key (e.g., ai.enable_ai_payloads)'
        )
        
        set_parser.add_argument(
            'value',
            help='Configuration value'
        )
        
        # Get configuration values
        config_subparsers.add_parser(
            'show',
            help='Show current configuration'
        )
    
    def _add_demo_parser(self, subparsers):
        """Add demo command parser"""
        demo_parser = subparsers.add_parser(
            'demo',
            help='Run DIVYASTRA demonstration',
            description='Demonstrate DIVYASTRA capabilities'
        )
        
        demo_parser.add_argument(
            '--target',
            default='testphp.vulnweb.com',
            help='Demo target (default: testphp.vulnweb.com)'
        )
        
        demo_parser.add_argument(
            '--mode',
            choices=['basic', 'comprehensive', 'nextgen'],
            default='comprehensive',
            help='Demo mode'
        )
    
    async def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI with given arguments"""
        try:
            parsed_args = self.parser.parse_args(args)
            
            # Show banner if requested or if no command
            if parsed_args.banner or not parsed_args.command:
                print(get_banner())
                if not parsed_args.command:
                    self.parser.print_help()
                    return 0
            
            # Load configuration if specified
            if parsed_args.config:
                self.config.load_from_file(parsed_args.config)
            
            # Set verbose logging if requested
            if parsed_args.verbose:
                import logging
                logging.getLogger().setLevel(logging.DEBUG)
            
            # Execute command
            return await self._execute_command(parsed_args)
            
        except KeyboardInterrupt:
            logger.info("Operation cancelled by user")
            return 130
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            return 1
    
    async def _execute_command(self, args) -> int:
        """Execute the specified command"""
        command_handlers = {
            'recon': self._handle_recon,
            'web': self._handle_web,
            'api': self._handle_api,
            'zero-day': self._handle_zero_day,
            'business-logic': self._handle_business_logic,
            'config': self._handle_config,
            'demo': self._handle_demo
        }
        
        handler = command_handlers.get(args.command)
        if handler:
            return await handler(args)
        else:
            logger.error(f"Unknown command: {args.command}")
            return 1
    
    async def _handle_recon(self, args) -> int:
        """Handle reconnaissance command"""
        logger.info(f"🔍 Starting reconnaissance on {args.target}")
        
        # Create reconnaissance instance
        config = {
            'max_workers': args.workers,
            'timeout': args.timeout,
            'deep_analysis': args.deep
        }
        
        recon = Reconnaissance(args.target, config)
        
        # Run reconnaissance
        results = recon.run_full_recon()
        
        # Save results
        await self._save_results(results, args, 'reconnaissance')
        
        logger.info("✅ Reconnaissance completed")
        return 0
    
    async def _handle_web(self, args) -> int:
        """Handle web security testing command"""
        logger.info(f"🌐 Starting web security testing on {args.target}")
        
        # Implementation for web security testing
        logger.info("Web security testing not yet implemented")
        return 0
    
    async def _handle_api(self, args) -> int:
        """Handle API security testing command"""
        logger.info(f"🔌 Starting API security testing on {args.target}")
        
        # Implementation for API security testing
        logger.info("API security testing not yet implemented")
        return 0
    
    async def _handle_zero_day(self, args) -> int:
        """Handle zero-day discovery command"""
        logger.info(f"🎯 Starting zero-day hunting on {args.target}")
        
        try:
            # Initialize components
            bus = EventBus()
            scope = Scope(args.target)
            
            # Create zero-day hunter
            hunter = ZeroDayHunterAgent(bus, scope, args.budget)
            
            # Execute zero-day hunting
            await hunter.execute()
            
            # Get results
            results = hunter.get_results()
            
            # Save results
            await self._save_results(results, args, 'zero_day')
            
            logger.info("✅ Zero-day hunting completed")
            return 0
            
        except Exception as e:
            logger.error(f"Zero-day hunting failed: {str(e)}")
            return 1
    
    async def _handle_business_logic(self, args) -> int:
        """Handle business logic testing command"""
        logger.info(f"🏢 Starting business logic testing on {args.target}")
        
        # Implementation for business logic testing
        logger.info("Business logic testing not yet implemented")
        return 0
    
    async def _handle_config(self, args) -> int:
        """Handle configuration management command"""
        if args.config_action == 'init':
            return self._init_config(args)
        elif args.config_action == 'set':
            return self._set_config(args)
        elif args.config_action == 'show':
            return self._show_config()
        else:
            logger.error("Configuration action required")
            return 1
    
    def _init_config(self, args) -> int:
        """Initialize DIVYASTRA configuration"""
        logger.info("🔧 Initializing DIVYASTRA configuration...")
        
        config_dir = Path.home() / '.divyastra'
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / 'config.json'
        
        default_config = {
            "reconnaissance": {
                "max_workers": 10,
                "timeout": 10,
                "enable_subdomain_enum": True,
                "enable_port_scan": True,
                "enable_tech_detection": True
            },
            "security_testing": {
                "enable_injection_testing": True,
                "enable_auth_testing": True,
                "enable_business_logic": False
            },
            "ai_capabilities": {
                "enable_ai_payloads": False,
                "confidence_threshold": 80,
                "auto_poc_generation": False
            },
            "reporting": {
                "format": "json",
                "include_evidence": True,
                "generate_dashboard": False
            }
        }
        
        if args.nextgen:
            default_config["ai_capabilities"]["enable_ai_payloads"] = True
            default_config["security_testing"]["enable_business_logic"] = True
            default_config["zero_day_hunting"] = {
                "enable_static_analysis": True,
                "enable_dynamic_analysis": True,
                "enable_intelligent_fuzzing": True,
                "pattern_mining": True,
                "novelty_threshold": 70
            }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        logger.info(f"✅ Configuration initialized at {config_file}")
        return 0
    
    def _set_config(self, args) -> int:
        """Set configuration value"""
        logger.info(f"Setting {args.key} = {args.value}")
        # Implementation for setting config values
        return 0
    
    def _show_config(self) -> int:
        """Show current configuration"""
        print(json.dumps(self.config.get_all(), indent=2))
        return 0
    
    async def _handle_demo(self, args) -> int:
        """Handle demo command"""
        logger.info(f"🎬 Running DIVYASTRA demo on {args.target}")
        
        # Run demo script
        try:
            from ..demo import main as demo_main
            demo_main(args.target)
            return 0
        except ImportError:
            logger.error("Demo module not found")
            return 1
    
    async def _save_results(self, results: Dict, args, scan_type: str):
        """Save scan results to file"""
        output_dir = Path(args.output) if args.output else Path.cwd() / 'reports'
        output_dir.mkdir(exist_ok=True)
        
        timestamp = int(time.time())
        filename = f"divyastra_{scan_type}_{results.get('target', 'unknown')}_{timestamp}.{args.format}"
        output_file = output_dir / filename
        
        if args.format == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        logger.info(f"📄 Results saved to {output_file}")

def main():
    """Main CLI entry point"""
    cli = DivyastraCLI()
    
    try:
        import asyncio
        return asyncio.run(cli.run())
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1

if __name__ == '__main__':
    sys.exit(main())