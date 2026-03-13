import click
from typing import Optional


@click.command(name='extract-cache')
@click.argument('tdata_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
@click.option('--passcode', '-p', help='Passcode for encrypted data')
def command(tdata_path: str, output_dir: str, passcode: Optional[str]):
    """Extract and decrypt cached TDEF files."""
    from ...parsers.tdata_parser import TDataParser

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
