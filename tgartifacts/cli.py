"""TGArtifacts CLI - Telegram Desktop forensic analysis tool."""
import click
from typing import Optional

from .parsers.tdata_parser import TDataParser

@click.group()
@click.version_option(version='0.1.0')
def cli():
    """TGArtifacts - Telegram Desktop artifact analysis tool.
    Extract and analyze data from Telegram Desktop's tdata directory.
    Only for educational purposes. Do not use as stealer instrument.
        By Dmeetrogon
    """
    pass


def _compute_auth_key_id(auth_key: bytes) -> str:
    """Compute auth_key_id from auth_key (lower 64 bits of SHA1).

    Args:
        auth_key: 256-byte auth key

    Returns:
        Hex string of auth_key_id
    """
    import hashlib
    sha1_hash = hashlib.sha1(auth_key).digest()
    return sha1_hash[-8:].hex()


@cli.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.option('--passcode', '-p', help='Passcode for encrypted data')
@click.option('--show-keys', '-k', is_flag=True, help='Show full auth keys (256 bytes hex)')
def info(tdata_path: str, passcode: Optional[str], show_keys: bool):
    """Show quick information about tdata directory structure.

    Args:
        tdata_path: Path to tdata directory
        passcode: Optional passcode
        show_keys: Show full auth keys
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

            auth_keys = info_data.get('auth_keys', {})
            if auth_keys:
                click.secho(f"    Auth keys: {len(auth_keys)} DC(s)", fg='cyan')
                for dc_id, auth_key in sorted(auth_keys.items()):
                    auth_key_id = _compute_auth_key_id(auth_key)
                    click.echo(f"      DC {dc_id}: auth_key_id = {auth_key_id}")
                    if show_keys:
                        key_hex = auth_key.hex()
                        click.echo(f"        auth_key = {key_hex[:64]}...")
                        click.echo(f"                   {key_hex[64:128]}...")
                        click.echo(f"                   {key_hex[128:192]}...")
                        click.echo(f"                   {key_hex[192:256]}...")
                        click.echo(f"                   {key_hex[256:320]}...")
                        click.echo(f"                   {key_hex[320:384]}...")
                        click.echo(f"                   {key_hex[384:448]}...")
                        click.echo(f"                   {key_hex[448:]}")
            keys_to_destroy = info_data.get('keys_to_destroy', {})
            if keys_to_destroy:
                click.secho(f"    Keys to destroy: {len(keys_to_destroy)} DC(s)", fg='yellow')

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
        tdef_files = parser.find_cached_tdef_files()
        if not tdef_files:
            click.secho("No cached TDEF files found", fg='yellow')
            return
        click.echo(f"Found {len(tdef_files)} cached file(s)")
        click.echo("Extracting...\n")
        stats = parser.extract_cached_tdef_files(output_dir)
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
def _create_telethon_string_session(dc_id: int, auth_key: bytes) -> str:
    """Create telethon StringSession from dc_id and auth_key.

    Telethon StringSession v1 format:
    '1' + base64url(dc_id[1] + ip[4] + port[2] + auth_key[256])

    Args:
        dc_id: Data center ID
        auth_key: 256-byte auth key

    Returns:
        Telethon StringSession string
    """
    import struct
    import base64

    session_data = struct.pack(
        '>B4sH256s',
        dc_id,
        b'\x00\x00\x00\x00',  # IP placeholder for telethon
        443,  
        auth_key
    )

    return '1' + base64.urlsafe_b64encode(session_data).decode('ascii')


@cli.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--passcode', '-p', help='Passcode for encrypted data')
@click.option('--format', '-f', 'output_format', type=click.Choice(['json', 'telethon']),
              default='json', help='Output format (json or telethon StringSession)')
def export_session(tdata_path: str, output_file: str, passcode: Optional[str], output_format: str):
    """Export session data (auth keys) from tdata.

    Args:
        tdata_path: Path to tdata directory
        output_file: Output file path
        passcode: Optional passcode
        output_format: Output format (json or telethon)
    """
    import json

    click.echo(f"Exporting session from: {tdata_path}\n")

    try:
        parser = TDataParser(tdata_path, passcode)
        accounts_info = parser.get_all_accounts_info()

        if not accounts_info:
            click.secho("No accounts found", fg='yellow')
            return

        export_data = []
        for info_data in accounts_info:
            if not info_data.get('success'):
                continue

            account_export = {
                'account_dir': info_data['account_dir'],
                'user_id': info_data.get('user_id'),
                'dc_id': info_data.get('dc_id'),
                'auth_keys': info_data.get('auth_keys', {}),
                'auth_keys_hex': {
                    str(dc): key.hex() for dc, key in info_data.get('auth_keys', {}).items()
                },
                'auth_key_ids': {
                    str(dc): _compute_auth_key_id(key)
                    for dc, key in info_data.get('auth_keys', {}).items()
                }
            }
            export_data.append(account_export)

        if output_format == 'json':
            # For JSON, convert bytes to hex
            json_data = []
            for account in export_data:
                json_account = {
                    'account_dir': account['account_dir'],
                    'user_id': account['user_id'],
                    'dc_id': account['dc_id'],
                    'auth_keys': account['auth_keys_hex'],
                    'auth_key_ids': account['auth_key_ids']
                }
                json_data.append(json_account)

            with open(output_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            click.secho(f"Session data exported to: {output_file}", fg='green')

        elif output_format == 'telethon':
            # Export as telethon StringSession
            with open(output_file, 'w') as f:
                for account in export_data:
                    dc_id = account['dc_id']
                    auth_keys = account.get('auth_keys', {})

                    if dc_id in auth_keys:
                        auth_key = auth_keys[dc_id]
                        string_session = _create_telethon_string_session(dc_id, auth_key)

                        f.write(f"# Account: {account['account_dir']}\n")
                        f.write(f"# User ID: {account['user_id']}\n")
                        f.write(f"# DC ID: {dc_id}\n")
                        f.write(f"# Auth Key ID: {account['auth_key_ids'].get(str(dc_id), 'N/A')}\n")
                        f.write(f"{string_session}\n\n")

                        click.echo(f"Account {account['user_id']}:")
                        click.secho(f"  StringSession: {string_session[:50]}...", fg='cyan')
                    else:
                        click.secho(f"Account {account['user_id']}: No auth key for DC {dc_id}", fg='yellow')

            click.secho(f"\nTelethon sessions exported to: {output_file}", fg='green')

        click.echo(f"Exported {len(export_data)} account(s)")

    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()


@cli.command()
@click.argument('session_string')
def validate_session(session_string: str):
    """Validate a Telethon StringSession by connecting to Telegram API.

    Requires telethon: pip install telethon

    SESSION_STRING: Telethon StringSession (starts with '1')

    Example:
        tgartifacts validate-session "1AgAAAAA..."
    """
    try:
        from .utils.session_validator import SessionValidator
    except ImportError:
        click.secho("Error: telethon not installed. Run: pip install telethon", fg='red', err=True)
        raise click.Abort()

    if not session_string.startswith('1'):
        click.secho("Error: Invalid StringSession format (should start with '1')", fg='red', err=True)
        raise click.Abort()

    click.echo("Validating session...\n")

    try:
        validator = SessionValidator()
        result = validator.validate_string_session(session_string)

        if result.valid:
            click.secho("✓ Session VALID", fg='green')
            click.echo(f"  User ID: {result.user_id}")
            click.echo(f"  Name: {result.first_name} {result.last_name or ''}")
            if result.username:
                click.echo(f"  Username: @{result.username}")
            if result.phone:
                click.echo(f"  Phone: {result.phone}")
        else:
            click.secho(f"✗ Session INVALID: {result.error}", fg='red')

    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()


if __name__ == '__main__':
    cli()
