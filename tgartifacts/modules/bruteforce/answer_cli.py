import click
from pathlib import Path


@click.command()
@click.argument('tdata_path', type=click.Path(exists=True))
@click.option('--wordlist', '-w', type=click.Path(exists=True), required=True, help='Password wordlist')
@click.option('--threads', '-t', type=int, default=1, help='Number of parallel processes (default: 1)')
def command(tdata_path: str, wordlist: str, threads: int):
    """Bruteforce tdata passcode using a wordlist.

    Speed is ~3 passwords/s per thread (limited by PBKDF2 100k iterations).
    Use --threads to parallelize across CPU cores.
    """
    from .bruteforcer import Bruteforcer

    try:
        bf = Bruteforcer(Path(tdata_path))
    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()

    def on_progress(attempts, elapsed):
        speed = attempts / elapsed if elapsed > 0 else 0
        click.echo(f"\r  Attempts: {attempts} | Speed: {speed:.1f}/s | Time: {elapsed:.1f}s", nl=False)

    click.echo(f"Wordlist: {wordlist}")
    click.echo(f"Threads: {threads}")
    click.echo(f"TDesktop version: {bf.version}\n")
    result = bf.bruteforce_wordlist(Path(wordlist), threads=threads, on_progress=on_progress)

    click.echo()
    if result.found:
        click.secho(f"\nPasscode found: {result.passcode}", fg='green')
        click.echo(f"Attempts: {result.attempts}")
        click.echo(f"Time: {result.elapsed:.2f}s")
        click.echo(f"Speed: {result.speed:.1f}/s")
    else:
        click.secho(f"\nPasscode not found", fg='red')
        click.echo(f"Attempts: {result.attempts}")
        click.echo(f"Time: {result.elapsed:.2f}s")
