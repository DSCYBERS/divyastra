from typing import Callable, Dict, List, Optional
import click
import json
from pathlib import Path

class Command:
    def __init__(self, name: str, handler: Callable, description: str = ""):
        self.name = name
        self.handler = handler
        self.description = description

class CommandRegistry:
    def __init__(self):
        self.commands: Dict[str, Command] = {}

    def register_command(self, command: Command):
        self.commands[command.name] = command

    def execute_command(self, name: str, *args, **kwargs):
        if name in self.commands:
            return self.commands[name].handler(*args, **kwargs)
        else:
            raise ValueError(f"Command '{name}' not found.")

    def list_commands(self):
        return [(name, cmd.description) for name, cmd in self.commands.items()]

class CommandHandler:
    def __init__(self):
        self.registry = CommandRegistry()
        self._register_commands()

    def _register_commands(self):
        """Register all available commands"""
        commands = [
            Command("scan", self.scan_command, "Automated vulnerability scanning and reconnaissance"),
            Command("exploit", self.exploit_command, "Execute validated exploits in sandbox"),
            Command("validate", self.validate_command, "Post-exploitation validation"),
            Command("report", self.report_command, "Generate compliance-ready reports"),
            Command("recon", self.recon_command, "Automated reconnaissance and OSINT"),
            Command("feeds", self.feeds_command, "Manage vulnerability feeds"),
            Command("config", self.config_command, "Configure settings and preferences"),
            Command("help", self.help_command, "Show help information")
        ]
        
        for cmd in commands:
            self.registry.register_command(cmd)

    def execute_command(self, args: List[str]):
        """Execute command with CLI arguments"""
        if not args or args[0] in ['-h', '--help']:
            self.help_command()
            return

        command_name = args[0]
        command_args = args[1:]
        
        try:
            self.registry.execute_command(command_name, command_args)
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
            self.help_command()

    def scan_command(self, args: List[str]):
        """Enhanced scan command with multiple options"""
        @click.command()
        @click.argument('target')
        @click.option('--scope', multiple=True, help='Define scan scope')
        @click.option('--aggression', type=click.Choice(['low', 'medium', 'high']), default='medium')
        @click.option('--mode', type=click.Choice(['web', 'network', 'cloud', 'api']), default='web')
        @click.option('--budget', type=int, help='Budget limit for scan operations')
        @click.option('--output', '-o', help='Output file path')
        @click.option('--format', type=click.Choice(['json', 'xml', 'sarif', 'pdf']), default='json')
        @click.option('--air-gapped', is_flag=True, help='Run in air-gapped mode')
        @click.option('--dry-run', is_flag=True, help='Audit mode without actual exploitation')
        def scan(target, scope, aggression, mode, budget, output, format, air_gapped, dry_run):
            click.echo(f"🎯 Starting DIVYASTRA scan on: {target}")
            click.echo(f"   Mode: {mode} | Aggression: {aggression}")
            if scope:
                click.echo(f"   Scope: {', '.join(scope)}")
            if budget:
                click.echo(f"   Budget: ${budget}")
            if dry_run:
                click.echo("   🔍 Running in DRY-RUN mode (no actual exploitation)")
            if air_gapped:
                click.echo("   🔒 Air-gapped mode enabled")
            
            # Here you would integrate with your core scanning modules
            
        # Parse the arguments manually for now
        scan.main(args, standalone_mode=False)

    def exploit_command(self, args: List[str]):
        """Exploit command with sandbox execution"""
        click.echo("🚀 Launching sandboxed exploit execution...")
        # Implementation would call your exploitation modules

    def validate_command(self, args: List[str]):
        """Post-exploitation validation"""
        click.echo("✅ Running post-exploitation validation...")
        # Implementation would call your validation modules

    def report_command(self, args: List[str]):
        """Generate comprehensive reports"""
        @click.command()
        @click.option('--format', type=click.Choice(['pdf', 'sarif', 'markdown', 'json']), default='pdf')
        @click.option('--template', type=click.Choice(['technical', 'executive', 'compliance']), default='technical')
        @click.option('--output', '-o', required=True, help='Output file path')
        @click.option('--language', default='en', help='Report language')
        def report(format, template, output, language):
            click.echo(f"📊 Generating {format.upper()} report...")
            click.echo(f"   Template: {template}")
            click.echo(f"   Language: {language}")
            click.echo(f"   Output: {output}")
            
        report.main(args, standalone_mode=False)

    def recon_command(self, args: List[str]):
        """Enhanced reconnaissance with OSINT"""
        click.echo("🔍 Starting automated reconnaissance...")
        # Implementation would call reconnaissance modules

    def feeds_command(self, args: List[str]):
        """Manage vulnerability feeds"""
        @click.command()
        @click.argument('action', type=click.Choice(['update', 'list', 'status']))
        @click.option('--source', multiple=True, help='Specific feed sources')
        def feeds(action, source):
            if action == 'update':
                click.echo("🔄 Updating vulnerability feeds...")
                if source:
                    click.echo(f"   Sources: {', '.join(source)}")
                else:
                    click.echo("   Updating all feeds (CVE/NVD, ExploitDB, OTX, etc.)")
            elif action == 'list':
                click.echo("📋 Available vulnerability feeds:")
                feeds_list = ['CVE/NVD', 'ExploitDB', 'AlienVault OTX', 'OWASP', 'HackerOne']
                for feed in feeds_list:
                    click.echo(f"   • {feed}")
            elif action == 'status':
                click.echo("📊 Feed status:")
                
        feeds.main(args, standalone_mode=False)

    def config_command(self, args: List[str]):
        """Configuration management"""
        click.echo("⚙️  Configuration management...")
        # Implementation for managing configurations

    def help_command(self, args: List[str] = None):
        """Display help information"""
        click.echo("🗡️  DIVYASTRA - AI-Powered Penetration Testing Suite")
        click.echo()
        click.echo("Available commands:")
        
        for name, description in self.registry.list_commands():
            click.echo(f"  {name:<12} {description}")
        
        click.echo()
        click.echo("Examples:")
        click.echo("  divyastra scan example.com --mode web --aggression medium")
        click.echo("  divyastra recon example.com --osint --subdomains")
        click.echo("  divyastra report --format pdf --template executive -o report.pdf")
        click.echo("  divyastra feeds update --source cve,exploitdb")

# Initialize command handler
command_handler = CommandHandler()