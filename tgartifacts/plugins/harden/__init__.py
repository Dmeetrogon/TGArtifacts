from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext


class HardenPlugin(BasePlugin):
    name = "harden"
    description = "Auto-fix security issues found by audit (file permissions, directory access)"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        from .answer_cli import run
        return run(context)
