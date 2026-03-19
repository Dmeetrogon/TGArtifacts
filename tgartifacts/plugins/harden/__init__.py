import click
from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext
from .hardener import Hardener


class HardenPlugin(BasePlugin):
    name = "harden"
    description = "Auto-fix security issues found by audit (file permissions, directory access)"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        hardener = Hardener(context.tdata_path)
        fixable, manual = hardener.analyze()

        if not fixable and not manual:
            click.secho("No issues found — nothing to fix.", fg='green')
            return {"applied": 0, "skipped": 0, "manual": 0}

        click.echo(f"Hardening: {context.tdata_path}\n")

        applied = 0
        skipped = 0

        for action in fixable:
            f = action.finding
            d3 = f" ({f.d3fend_id})" if f.d3fend_id else ""
            click.echo(f"  {f.title}: {f.remediation}{d3}")
            if click.confirm("    Apply fix?", default=False):
                try:
                    desc = hardener.apply(f)
                    click.secho(f"  [FIXED] {desc}", fg='green')
                    applied += 1
                except Exception as e:
                    click.secho(f"  [ERROR] {e}", fg='red')
                    skipped += 1
            else:
                click.secho("  [SKIPPED]", fg='yellow')
                skipped += 1
            click.echo()

        for f in manual:
            d3 = f" ({f.d3fend_id})" if f.d3fend_id else ""
            click.echo(f"  [MANUAL] {f.title} → {f.remediation}{d3}")

        click.echo(f"\nApplied: {applied} fixes")
        if skipped:
            click.echo(f"Skipped: {skipped}")
        if manual:
            click.echo(f"Manual action required: {len(manual)} items")

        return {
            "applied": applied,
            "skipped": skipped,
            "manual": len(manual),
        }
