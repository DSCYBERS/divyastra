# main.py

import sys
import click
from divyastra.cli.commands import command_handler

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """DIVYASTRA - AI-Powered Penetration Testing Suite"""
    if ctx.invoked_subcommand is None:
        command_handler.help_command()

def main():
    """Main entry point for DIVYASTRA"""
    try:
        if len(sys.argv) == 1:
            command_handler.help_command()
        else:
            command_handler.execute_command(sys.argv[1:])
    except KeyboardInterrupt:
        click.echo("\n⚠️  Operation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == "__main__":
    main()