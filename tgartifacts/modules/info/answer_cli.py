import hashlib
from datetime import datetime
import click
from typing import Any, Dict, Optional


def _compute_auth_key_id(auth_key: bytes) -> str:
    return hashlib.sha1(auth_key).digest()[-8:].hex()


def _display_settings(settings: Dict[str, Any]) -> None:
    if not settings:
        click.echo("  Settings: could not decrypt")
        return

    click.secho("Settings:", fg='cyan', bold=True)

    bools = [
        ("auto_start", "Auto start"),
        ("start_minimized", "Start minimized"),
        ("send_to_menu", "Send to menu"),
        ("seen_tray_tooltip", "Seen tray tooltip"),
        ("auto_update", "Auto update"),
    ]
    for key, label in bools:
        if key in settings:
            val = settings[key]
            color = "green" if val else "red"
            click.echo(f"  {label}: ", nl=False)
            click.secho(str(val), fg=color)

    if "last_update_check" in settings:
        ts = settings["last_update_check"]
        if ts > 0:
            try:
                dt = datetime.fromtimestamp(ts)
                click.echo(f"  Last update check: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            except (OSError, ValueError):
                click.echo(f"  Last update check: {ts}")
        else:
            click.echo(f"  Last update check: never")

    if "scale_percent" in settings:
        scale = settings["scale_percent"]
        click.echo(f"  Scale: {scale}%" if scale > 0 else "  Scale: auto")

    if "auto_lock" in settings:
        click.echo(f"  Auto lock: {settings['auto_lock']}s")

    if "power_saving" in settings:
        click.echo(f"  Power saving: {settings['power_saving']}")

    if "phone_number" in settings:
        click.secho(f"  Phone number: {settings['phone_number']}", fg='yellow')

    if "download_path" in settings:
        click.echo(f"  Download path: {settings['download_path']}")

    if "dialog_last_path" in settings:
        click.echo(f"  Last dialog path: {settings['dialog_last_path']}")

    if "lang_pack_key" in settings:
        click.echo(f"  Language: {settings['lang_pack_key']}")

    if "send_key" in settings:
        sk = {0: "Enter", 1: "Ctrl+Enter"}.get(settings["send_key"], str(settings["send_key"]))
        click.echo(f"  Send key: {sk}")

    theme = settings.get("theme")
    if theme:
        mode = "night" if theme.get("night_mode") else "day"
        click.echo(f"  Theme mode: {mode}")

    bg = settings.get("background")
    if bg:
        click.echo(f"  Background ID: day={bg.get('day', 0)}, night={bg.get('night', 0)}")

    wp = settings.get("window_position")
    if wp:
        click.echo(f"  Window position: {wp.get('w', 0)}x{wp.get('h', 0)} at ({wp.get('x', 0)}, {wp.get('y', 0)})")

    conn = settings.get("connection")
    if conn:
        ctype = {0: "auto", 1: "HTTP proxy", 2: "TCP proxy", 3: "MTPROTO proxy"}.get(
            conn.get("type", 0), str(conn.get("type", 0))
        )
        click.echo(f"  Connection type: {ctype}")
        if conn.get("proxy_host"):
            click.echo(f"  Proxy: {conn['proxy_host']}:{conn.get('proxy_port', 0)}")

    config = settings.get("production_config")
    if config:
        dc_opts = config.get("dc_options", [])
        dc_ids = sorted({opt["dc_id"] for opt in dc_opts})
        click.echo(f"  DC options: {len(dc_opts)} entries ({len(dc_ids)} DCs: {', '.join(map(str, dc_ids))})")
        click.echo(f"  Chat size max: {config.get('chat_size_max', 'N/A')}")
        click.echo(f"  Megagroup size max: {config.get('megagroup_size_max', 'N/A')}")

    click.echo()


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

        click.secho(f"TDesktop version: {parser.tdesktop_version}\n", fg='cyan', bold=True)

        settings = parser.get_settings_info()
        _display_settings(settings)

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
