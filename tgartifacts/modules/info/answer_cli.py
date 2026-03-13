import hashlib
import click
from typing import Optional


def _compute_auth_key_id(auth_key: bytes) -> str:
    return hashlib.sha1(auth_key).digest()[-8:].hex()


@click.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.option('--passcode', '-p', help='Passcode for encrypted data')
@click.option('--show-keys', '-k', is_flag=True, help='Show full auth keys')
def command(tdata_path: str, passcode: Optional[str], show_keys: bool):
    """Show information about tdata directory."""
    from ...parsers.tdata_parser import TDataParser

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
                        for i in range(0, len(key_hex), 64):
                            click.echo(f"        {key_hex[i:i+64]}")

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
