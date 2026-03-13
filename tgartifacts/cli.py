import click

from .modules import register_modules


@click.group()
@click.version_option(version='0.1.0')
def cli():
    """TGArtifacts - Telegram Desktop artifact analysis tool."""
    pass


register_modules(cli)


if __name__ == '__main__':
    cli()
