import click
from pathlib import Path


@click.command()
@click.argument('tdata_path', type=click.Path(exists=True))
def command(tdata_path: str):
    """Security audit of a tdata directory.

    Checks passcode strength, file permissions, encryption version,
    and maps findings to MITRE ATT&CK / D3FEND techniques.
    """
    from .auditor import Auditor

    try:
        auditor = Auditor(Path(tdata_path))
    except Exception as e:
        click.secho(f"Error: {e}", fg='red', err=True)
        raise click.Abort()

    click.echo(f"Auditing: {tdata_path}\n")
    report = auditor.audit()

    severity_colors = {
        'CRITICAL': 'red',
        'WARNING': 'yellow',
        'INFO': 'cyan',
    }

    for finding in report.findings:
        color = severity_colors.get(finding.severity, 'white')
        tag = click.style(f"[{finding.severity}]", fg=color)
        mitre = f" ({finding.mitre_id})" if finding.mitre_id else ""
        click.echo(f"  {tag} {finding.title}{mitre}")
        click.echo(f"    {finding.detail}")
        click.echo()

    click.echo("---")
    click.echo(f"  Version: {report.version}")
    click.echo(f"  Accounts: {report.accounts_count}")
    click.echo(f"  Passcode set: {'yes' if report.passcode_set else 'no'}")
    if report.passcode_weak is not None:
        weak_str = click.style('WEAK', fg='red') if report.passcode_weak else click.style('not in top-50', fg='green')
        click.echo(f"  Passcode strength: {weak_str}")

    total = len(report.findings)
    click.echo(f"\n  Findings: {report.critical_count} critical, {report.warning_count} warnings, "
               f"{total - report.critical_count - report.warning_count} info")
