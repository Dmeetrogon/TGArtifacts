import click
from collections import OrderedDict
from typing import Any, Dict, List

from tgartifacts.plugins import PluginContext
from .analyzer import TimelineAnalyzer, TimelineEvent


def _render_tree(events: List[TimelineEvent], max_entries: int = 50) -> str:
    grouped = OrderedDict()
    for e in events:
        day = e.timestamp.strftime('%Y-%m-%d')
        grouped.setdefault(day, []).append(e)

    lines = []
    days = list(grouped.keys())
    total_shown = 0

    for day_idx, day in enumerate(days):
        is_last_day = day_idx == len(days) - 1
        day_events = grouped[day]
        lines.append(f"  {'└' if is_last_day else '├'}── {day}  ({len(day_events)} files)")

        prefix = "      " if is_last_day else "  │   "
        remaining = max_entries - total_shown
        show = day_events[:remaining]

        for i, e in enumerate(show):
            is_last = (i == len(show) - 1) and (len(show) == len(day_events) or remaining <= len(day_events))
            connector = '└' if is_last else '├'
            lines.append(f"{prefix}{connector}── {e.timestamp:%H:%M:%S}  {e.path}")
            total_shown += 1

        if len(day_events) > len(show):
            lines.append(f"{prefix}└── ... +{len(day_events) - len(show)} more")
            total_shown = max_entries

        if total_shown >= max_entries:
            remaining_days = len(days) - day_idx - 1
            if remaining_days > 0:
                lines.append(f"  └── ... +{remaining_days} more day(s)")
            break

    return '\n'.join(lines)


def run(context: PluginContext) -> Dict[str, Any]:
    analyzer = TimelineAnalyzer(context.tdata_path, context.accounts)
    report = analyzer.analyze()

    click.echo(f"Timeline: {context.tdata_path}")
    click.echo(f"  Files analyzed: {report.total_files}")
    if report.earliest and report.latest:
        click.echo(f"  Period: {report.earliest:%Y-%m-%d %H:%M:%S} — "
                   f"{report.latest:%Y-%m-%d %H:%M:%S}")
    click.echo()

    if report.anomalies:
        click.echo("Anomalies detected:")
        for a in report.anomalies:
            color = 'red' if a.severity == 'CRITICAL' else 'yellow'
            click.secho(f"  [{a.severity}] {a.title} ({a.mitre_id})", fg=color)
            click.echo(f"    {a.detail}")
            click.echo()
    else:
        click.secho("  No anomalies detected.", fg='green')
        click.echo()

    click.echo("Activity tree:")
    click.echo(_render_tree(report.events))

    return {
        "total_files": report.total_files,
        "anomalies_count": len(report.anomalies),
        "anomalies": [
            {
                "severity": a.severity,
                "title": a.title,
                "detail": a.detail,
                "mitre_id": a.mitre_id,
                "events_count": len(a.events),
            }
            for a in report.anomalies
        ],
        "earliest": str(report.earliest) if report.earliest else None,
        "latest": str(report.latest) if report.latest else None,
        "recent_activity": [
            {"timestamp": str(e.timestamp), "path": e.path}
            for e in report.events[-10:]
        ],
    }
