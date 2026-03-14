import click


@click.command(name='validate-session')
@click.argument('session_string')
def command(session_string: str):
    """Validate a Telethon StringSession."""
    try:
        from ...utils.session_validator import SessionValidator
    except ImportError:
        click.secho("Error: telethon not installed. Run: pip install telethon", fg='red', err=True)
        raise click.Abort()

    if not session_string.startswith('1'):
        click.secho("Error: Invalid StringSession format", fg='red', err=True)
        raise click.Abort()

    click.echo("Validating session...\n")
    try:
        validator = SessionValidator()
        result = validator.validate_string_session(session_string)
        if result.valid:
            click.secho("Session VALID", fg='green')
            click.echo(f"  User ID: {result.user_id}")
            click.echo(f"  Name: {result.first_name} {result.last_name or ''}")
            if result.username:
                click.echo(f"  Username: @{result.username}")
            if result.phone:
                click.echo(f"  Phone: {result.phone}")
        else:
            click.secho(f"Session INVALID: {result.error}", fg='red')
    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()
