import click
from pathlib import Path
from typing import Optional


@click.command(name='list-plugins')
@click.option('--plugins-dir', type=click.Path(exists=True), default=None, help='Custom plugins directory')
def command(plugins_dir: Optional[str]):
    """List all available plugins."""
    from ...plugins import PluginManager

    manager = PluginManager()
    builtin_dir = Path(__file__).parent.parent.parent / 'plugins' / 'contrib'
    manager.load_from_directory(builtin_dir)

    if plugins_dir:
        manager.load_from_directory(Path(plugins_dir))

    plugins = manager.list_plugins()
    if not plugins:
        click.echo("No plugins found")
        return

    click.echo(f"Available plugins ({len(plugins)}):\n")
    for p in plugins:
        click.echo(f"  {p['name']} v{p['version']}")
        click.echo(f"    {p['description']}\n")
