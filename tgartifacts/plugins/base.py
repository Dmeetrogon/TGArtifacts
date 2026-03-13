from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from pathlib import Path


@dataclass
class PluginContext:
    tdata_path: Path
    local_key: Optional[bytes] = None
    passcode: Optional[str] = None
    accounts: List[Dict[str, Any]] = field(default_factory=list)
    cache_files: List[Path] = field(default_factory=list)
    output_dir: Optional[Path] = None


class BasePlugin(ABC):
    name: str = "unnamed"
    description: str = ""
    version: str = "0.1.0"

    @abstractmethod
    def run(self, context: PluginContext) -> Dict[str, Any]:
        ...
