from typing import Any, Dict

from tgartifacts.plugins import PluginContext
from .report import generate_report


def run(context: PluginContext) -> Dict[str, Any]:
    target_dir = context.output_dir or context.tdata_path
    if not target_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {target_dir}")
    return generate_report(target_dir)
