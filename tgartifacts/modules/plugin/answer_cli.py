import click
from pathlib import Path
from typing import Optional


@click.command()
@click.argument('plugin_name')
@click.argument('tdata_path', type=click.Path(exists=True))
@click.option('--passcode', '-p', help='Passcode for encrypted data')
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--plugins-dir', type=click.Path(exists=True), default=None, help='Custom plugins directory')
def command(plugin_name: str, tdata_path: str, passcode: Optional[str],
            output: Optional[str], plugins_dir: Optional[str]):
    """Run a plugin on tdata directory."""
    from ...plugins import PluginManager, PluginContext
    from ...parsers.tdata_parser import TDataParser

    manager = PluginManager()
    builtin_dir = Path(__file__).parent.parent.parent / 'plugins'
    manager.load_from_directory(builtin_dir)

    if plugins_dir:
        manager.load_from_directory(Path(plugins_dir))

    try:
        plugin_cls = manager.get(plugin_name)
    except KeyError as e:
        click.secho(str(e), fg='red')
        raise click.Abort()

    try:
        parser = TDataParser(tdata_path, passcode)
        context = PluginContext(
            tdata_path=Path(tdata_path),
            passcode=passcode,
            accounts=parser.get_all_accounts_info(),
            cache_files=parser.find_cached_tdef_files(),
            output_dir=Path(output) if output else None,
        )
        click.echo(f"Running plugin: {plugin_cls.name} v{plugin_cls.version}")
        result = plugin_cls().run(context)
        click.secho("Plugin completed successfully", fg='green')
        for key, value in result.items():
            if isinstance(value, dict) and len(value) > 10:
                click.echo(f"  {key}: {len(value)} entries")
            else:
                click.echo(f"  {key}: {value}")
    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()
