"""TGArtifacts CLI - Telegram Desktop forensic analysis tool."""
import click
from pathlib import Path
from typing import Optional

from .parsers.tdata_parser import TDataParser


@click.group()
@click.version_option(version='0.1.0')
def cli():
    """TGArtifacts - Telegram Desktop artifact analysis tool.

    Extract and analyze data from Telegram Desktop's tdata directory.
    """
    pass


@cli.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.option('--passcode', '-p', help='Passcode for encrypted data')
def info(tdata_path: str, passcode: Optional[str]):
    """Show quick information about tdata directory structure.

    Args:
        tdata_path: Path to tdata directory
        passcode: Optional passcode
    """
    click.echo(f"Analyzing tdata: {tdata_path}\n")

    try:
        parser = TDataParser(tdata_path, passcode)
        accounts_info = parser.get_all_accounts_info()
        click.echo(f"Found {len(accounts_info)} account(s):\n")
        for info_data in accounts_info:
            click.echo(f"  Account: {info_data['account_dir']}")

            if not info_data['success']:
                click.secho(f"    Error: {info_data['error']}", fg='red')
                continue
            if 'user_id' in info_data:
                click.secho(f"    User ID: {info_data['user_id']}", fg='green')
            if 'dc_id' in info_data:
                click.echo(f"    DC ID: {info_data['dc_id']}")
            passcode_status = "Yes" if info_data.get('has_passcode') else "No"
            click.echo(f"    Passcode protected: {passcode_status}")
            click.echo()
        tdef_files = parser.find_cached_tdef_files()
        if tdef_files:
            click.secho(f"Cached TDEF files: {len(tdef_files)} file(s)", fg='cyan')
        else:
            click.echo("Cached TDEF files: None found")

    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()
@cli.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.option('--passcode', '-p', help='Passcode for encrypted data')
@click.option('--account', '-a', help='Specific account directory to analyze')
@click.option('--output', '-o', type=click.Path(), help='Output file (HTML report)')
def analyze(tdata_path: str, passcode: Optional[str], account: Optional[str], output: Optional[str]):
    """Perform full analysis of tdata directory.

    Args:
        tdata_path: Path to tdata directory
        passcode: Optional passcode
        account: Specific account to analyze
        output: Output file path
    """
    click.echo(f"Analyzing tdata: {tdata_path}")

    if passcode:
        click.echo(f"Using passcode for decryption")
    click.echo()
    try:
        parser = TDataParser(tdata_path, passcode)

        if account:
            # Analyze specific account
            click.echo(f"Analyzing account: {account}\n")
            info_data = parser.get_account_info(account)
            _display_account_info(info_data)
        else:
            # Analyze all accounts
            accounts_info = parser.get_all_accounts_info()
            click.echo(f"Found {len(accounts_info)} account(s)\n")

            for info_data in accounts_info:
                _display_account_info(info_data)
                click.echo()

        # TODO: Generate HTML report if output specified
        if output:
            click.echo(f"\nHTML report generation not yet implemented")
            click.echo(f"Would save to: {output}")

    except Exception as e:
        click.secho(f"\nError: {e}", fg='red', err=True)
        raise click.Abort()
def _display_account_info(info: dict):
    """Display account information in terminal.

    Args:
        info: Account information dictionary
    """
    click.echo(f"Account: {info['account_dir']}")

    if not info['success']:
        click.secho(f"  Error: {info['error']}", fg='red')
        return

    # Display user data if available
    if 'user_id' in info:
        click.secho(f"  User ID: {info['user_id']}", fg='green')

    if 'dc_id' in info:
        click.echo(f"  DC ID: {info['dc_id']}")

    if 'phone' in info and info['phone']:
        click.secho(f"  Phone: {info['phone']}", fg='cyan')

    if 'entry_count' in info:
        click.echo(f"  Entries: {info['entry_count']}")

    if 'has_passcode' in info:
        status = "Yes" if info['has_passcode'] else "No"
        click.echo(f"  Passcode protected: {status}")


@cli.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
@click.option('--passcode', '-p', help='Passcode for encrypted data')
def extract_cache(tdata_path: str, output_dir: str, passcode: Optional[str]):
    """Extract and decrypt cached TDEF files from tdata.

    Args:
        tdata_path: Path to tdata directory
        output_dir: Output directory for decrypted files
        passcode: Optional passcode
    """
    click.echo(f"Extracting cached files from: {tdata_path}")
    click.echo(f"Output directory: {output_dir}\n")

    try:
        parser = TDataParser(tdata_path, passcode)

        # Find TDEF files
        tdef_files = parser.find_cached_tdef_files()
        if not tdef_files:
            click.secho("No cached TDEF files found", fg='yellow')
            return

        click.echo(f"Found {len(tdef_files)} cached file(s)")
        click.echo("Extracting...\n")

        # Extract files
        stats = parser.extract_cached_tdef_files(output_dir)

        # Display results
        click.secho(f"\nExtraction complete!", fg='green')
        click.echo(f"Total files: {stats['total']}")
        click.secho(f"Successfully decrypted: {stats['success']}", fg='green')
        if stats.get('streaming', 0) > 0:
            click.secho(f"Streaming cache reassembled: {stats['streaming']}", fg='cyan')
        if stats['failed'] > 0:
            click.secho(f"Failed: {stats['failed']}", fg='red')
        click.echo(f"\nDecrypted files saved to: {output_dir}")

    except Exception as e:
        click.secho(f"\nError: {e}", fg='red', err=True)
        raise click.Abort()


if __name__ == '__main__':
    cli()
