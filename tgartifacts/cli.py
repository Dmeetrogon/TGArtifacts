"""TGArtifacts CLI - Telegram Desktop forensic analysis tool."""
import click
from pathlib import Path
from typing import Optional

from .core.tdata_parser import TDataParser
from .core.bruteforce import PasscodeBruteforcer


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

        # Find all accounts
        accounts = parser.find_account_dirs()
        click.echo(f"Found {len(accounts)} account(s):\n")

        for account_dir in accounts:
            click.echo(f"  {account_dir}")

        click.echo()

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
        click.echo("Using passcode for decryption")

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
@click.option('--account', '-a', required=True, help='Account directory to bruteforce')
@click.option('--wordlist', '-w', type=click.Path(exists=True), help='Path to wordlist file (e.g., rockyou.txt)')
@click.option('--numeric', '-n', is_flag=True, help='Try numeric PINs (4-6 digits)')
@click.option('--common', '-c', is_flag=True, help='Try common patterns only')
@click.option('--max-attempts', '-m', type=int, help='Maximum attempts')
def bruteforce(tdata_path: str, account: str, wordlist: Optional[str], numeric: bool, common: bool, max_attempts: Optional[int]):
    """Bruteforce passcode for encrypted tdata.

    Args:
        tdata_path: Path to tdata directory
        account: Account directory name
        wordlist: Path to wordlist file
        numeric: Try numeric PINs
        common: Try common patterns
        max_attempts: Maximum attempts
    """
    click.echo(f"Bruteforcing passcode for: {tdata_path}/{account}\n")

    bruteforcer = PasscodeBruteforcer(tdata_path)

    # Get map file path
    account_path = Path(tdata_path) / account
    map_file = None
    for filename in ['maps', 'map0', 'map1']:
        candidate = account_path / filename
        if candidate.exists():
            map_file = candidate
            break

    if not map_file:
        click.secho("Error: Map file not found", fg='red', err=True)
        raise click.Abort()

    try:
        # Get salt
        salt = bruteforcer.get_salt_from_file(str(map_file))
        click.echo(f"Salt: {len(salt)} bytes")
        click.echo(f"Map file: {map_file.name}")

        # Detect if using new encryption
        from .core.bruteforce import get_key_datas_version
        version = get_key_datas_version(tdata_path)
        use_sha512 = version is not None and version >= 2001014

        if use_sha512:
            click.secho("Detected Telegram Desktop 2.1.14+ (SHA512 encryption)", fg='yellow')
        else:
            click.echo("Using legacy encryption (SHA1)")

        click.echo()

        found_passcode = None

        # Progress callback
        def progress(attempts: int, password: str):
            if attempts % 100 == 0:
                click.echo(f"Attempts: {attempts} | Current: {password[:20]}", nl=False)
                click.echo('\r', nl=False)

        # Try common patterns first
        if common or (not wordlist and not numeric):
            click.echo("Trying common patterns...")
            found_passcode = bruteforcer.bruteforce_common_patterns(
                str(map_file),
                salt,
                callback=progress,
                use_sha512=use_sha512
            )

            if found_passcode is not None:
                click.echo(f"\n")
                click.secho(f"SUCCESS! Passcode found: '{found_passcode}'", fg='green', bold=True)
                click.echo(f"Total attempts: {bruteforcer.attempts}")
                return

            click.echo(f"Common patterns failed ({bruteforcer.attempts} attempts)\n")

        # Try numeric PINs
        if numeric and found_passcode is None:
            click.echo("Trying numeric PINs (4-6 digits)...")
            found_passcode = bruteforcer.bruteforce_numeric(
                str(map_file),
                salt,
                min_length=4,
                max_length=6,
                callback=progress,
                use_sha512=use_sha512
            )

            if found_passcode is not None:
                click.echo(f"\n")
                click.secho(f"SUCCESS! Passcode found: '{found_passcode}'", fg='green', bold=True)
                click.echo(f"Total attempts: {bruteforcer.attempts}")
                return

            click.echo(f"Numeric bruteforce failed ({bruteforcer.attempts} attempts)\n")

        # Try wordlist
        if wordlist and found_passcode is None:
            click.echo(f"Using wordlist: {wordlist}")
            found_passcode = bruteforcer.bruteforce_from_wordlist(
                wordlist,
                str(map_file),
                salt,
                max_attempts=max_attempts,
                callback=progress,
                use_sha512=use_sha512
            )

            if found_passcode is not None:
                click.echo(f"\n")
                click.secho(f"SUCCESS! Passcode found: '{found_passcode}'", fg='green', bold=True)
                click.echo(f"Total attempts: {bruteforcer.attempts}")
                return

            click.echo(f"\nWordlist bruteforce failed ({bruteforcer.attempts} attempts)")

        if found_passcode is None:
            click.secho("\nPasscode not found", fg='red')

    except Exception as e:
        click.secho(f"\nError: {e}", fg='red', err=True)
        raise click.Abort()


if __name__ == '__main__':
    cli()
