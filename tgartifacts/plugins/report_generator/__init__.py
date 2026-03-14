from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext
from .collector import collect_report_data
from .json_report.renderer import render_json
from .html_report.renderer import render_html


class ReportGeneratorPlugin(BasePlugin):
    name = "report-generator"
    description = "Full forensic report: extract cache, sessions, validate, hash — HTML + JSON"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        if not context.output_dir:
            raise ValueError("Output directory required (-o flag)")

        data = collect_report_data(context.tdata_path, context.passcode, context.output_dir)

        report_dir = context.output_dir / "report"
        render_json(data, report_dir / "report.json")
        render_html(data, report_dir / "report.html")

        return {
            "accounts": len(data["accounts"]),
            "cache_extracted": data["cache"].get("success", 0),
            "report_json": str(report_dir / "report.json"),
            "report_html": str(report_dir / "report.html"),
        }
