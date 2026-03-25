import click
from typing import Any, Dict

from tgartifacts.plugins import PluginContext
from tgartifacts.plugins.timeline.analyzer import TimelineAnalyzer
from .auditor import Auditor

SEVERITY_COLORS = {
    'CRITICAL': 'red',
    'WARNING': 'yellow',
    'INFO': 'cyan',
}


def run(context: PluginContext) -> Dict[str, Any]:
    auditor = Auditor(context.tdata_path)

    click.echo(f"Auditing: {context.tdata_path}\n")
    report = auditor.audit()

    for finding in report.findings:
        color = SEVERITY_COLORS.get(finding.severity, 'white')
        tag = click.style(f"[{finding.severity}]", fg=color)
        mitre = f" ({finding.mitre_id})" if finding.mitre_id else ""
        click.echo(f"  {tag} {finding.title}{mitre}")
        click.echo(f"    {finding.detail}")
        click.echo()

    analyzer = TimelineAnalyzer(context.tdata_path, context.accounts)
    timeline = analyzer.analyze()

    if timeline.anomalies:
        click.echo("Timeline anomalies:")
        for a in timeline.anomalies:
            color = SEVERITY_COLORS.get(a.severity, 'white')
            tag = click.style(f"[{a.severity}]", fg=color)
            click.echo(f"  {tag} {a.title} ({a.mitre_id})")
            click.echo(f"    {a.detail}")
            click.echo()

    click.echo("---")
    click.echo(f"  Version: {report.version}")
    click.echo(f"  Accounts: {report.accounts_count}")
    click.echo(f"  Passcode set: {'yes' if report.passcode_set else 'no'}")
    click.echo(f"  Files analyzed: {timeline.total_files}")
    if timeline.earliest and timeline.latest:
        click.echo(f"  Activity period: {timeline.earliest:%Y-%m-%d} — {timeline.latest:%Y-%m-%d}")

    total_findings = len(report.findings)
    total_anomalies = len(timeline.anomalies)
    click.echo(f"\n  Findings: {report.critical_count} critical, {report.warning_count} warnings, "
               f"{total_findings - report.critical_count - report.warning_count} info")
    if total_anomalies:
        click.echo(f"  Timeline anomalies: {total_anomalies}")

    actionable = [f for f in report.findings if f.remediation]
    if actionable:
        click.echo(f"\nRecommendations:")
        for i, f in enumerate(actionable, 1):
            color = SEVERITY_COLORS.get(f.severity, 'white')
            tag = click.style(f"[{f.severity}]", fg=color)
            d3 = f" ({f.d3fend_id})" if f.d3fend_id else ""
            auto = click.style(" [auto-fixable: tgartifacts plugin harden]", fg='green') if f.auto_fixable else ""
            click.echo(f"  {i}. {tag} {f.remediation}{d3}{auto}")

    return {
        "version": report.version,
        "accounts": report.accounts_count,
        "passcode_set": report.passcode_set,
        "findings_critical": report.critical_count,
        "findings_warning": report.warning_count,
        "findings_total": total_findings,
        "timeline_files": timeline.total_files,
        "timeline_anomalies": total_anomalies,
    }
