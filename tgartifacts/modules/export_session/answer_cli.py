import hashlib
import json
import os
import struct
import base64
import click
from typing import Optional


def _compute_auth_key_id(auth_key: bytes) -> str:
    return hashlib.sha1(auth_key).digest()[-8:].hex()


def _create_telethon_string_session(dc_id: int, auth_key: bytes) -> str:
    session_data = struct.pack('>B4sH256s', dc_id, b'\x00\x00\x00\x00', 443, auth_key)
    return '1' + base64.urlsafe_b64encode(session_data).decode('ascii')


@click.command(name='export-session')
@click.argument('tdata_path', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--passcode', '-p', help='Passcode for encrypted data')
@click.option('--format', '-f', 'output_format', type=click.Choice(['json', 'telethon']),
              default='json', help='Output format')
def command(tdata_path: str, output_file: str, passcode: Optional[str], output_format: str):
    """Export session data from tdata."""
    from ...parsers.tdata_parser import TDataParser

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
            export_data.append({
                'account_dir': info_data['account_dir'],
                'user_id': info_data.get('user_id'),
                'dc_id': info_data.get('dc_id'),
                'auth_keys': info_data.get('auth_keys', {}),
                'auth_keys_hex': {str(dc): key.hex() for dc, key in info_data.get('auth_keys', {}).items()},
                'auth_key_ids': {str(dc): _compute_auth_key_id(key) for dc, key in info_data.get('auth_keys', {}).items()}
            })

        if output_format == 'json':
            json_data = [{
                'account_dir': a['account_dir'],
                'user_id': a['user_id'],
                'dc_id': a['dc_id'],
                'auth_keys': a['auth_keys_hex'],
                'auth_key_ids': a['auth_key_ids']
            } for a in export_data]
            fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(json_data, f, indent=2)
            click.secho(f"Session data exported to: {output_file}", fg='green')

        elif output_format == 'telethon':
            fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                for account in export_data:
                    dc_id = account['dc_id']
                    auth_keys = account.get('auth_keys', {})
                    if dc_id in auth_keys:
                        string_session = _create_telethon_string_session(dc_id, auth_keys[dc_id])
                        f.write(f"# Account: {account['account_dir']}\n")
                        f.write(f"# User ID: {account['user_id']}\n")
                        f.write(f"# DC ID: {dc_id}\n")
                        f.write(f"{string_session}\n\n")
                        click.echo(f"Account {account['user_id']}:")
                        click.secho(f"  StringSession: {string_session[:8]}...{string_session[-8:]}", fg='cyan')
                    else:
                        click.secho(f"Account {account['user_id']}: No auth key for DC {dc_id}", fg='yellow')
            click.secho(f"\nTelethon sessions exported to: {output_file}", fg='green')

        click.echo(f"Exported {len(export_data)} account(s)")

    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()
