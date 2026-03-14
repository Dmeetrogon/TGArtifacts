import click
from pathlib import Path


@click.command()
@click.option('--path', '-p', type=click.Path(), multiple=True, help='Extra paths to scan')
def command(path: tuple):
    """Auto-detect Telegram Desktop tdata directories.

    Searches standard locations: native install, snap, flatpak.
    Use --path to add custom locations.
    """
    from .scanner import scan_tdata

    extra = [Path(p) for p in path] if path else None
    locations = scan_tdata(extra_paths=extra)

    if not locations:
        click.secho("No tdata directories found", fg='yellow')
        return

    click.echo(f"Found {len(locations)} tdata location(s):\n")
    for loc in locations:
        status = click.style('VALID', fg='green') if loc.is_valid else click.style('INCOMPLETE', fg='yellow')
        click.echo(f"  [{status}] {loc.path}")
        click.echo(f"    Source: {loc.source}")
        click.echo(f"    key_datas: {'yes' if loc.has_key_datas else 'no'}")
        click.echo(f"    Accounts: {len(loc.account_dirs)}")
        if loc.account_dirs:
            for acc in loc.account_dirs:
                click.echo(f"      - {acc}")
        click.echo()
