import importlib.util
from pathlib import Path
from typing import Dict, Type

from .base import BasePlugin


class PluginManager:
    def __init__(self):
        self._plugins: Dict[str, Type[BasePlugin]] = {}

    @property
    def plugins(self) -> Dict[str, Type[BasePlugin]]:
        return dict(self._plugins)

    def register(self, plugin_class: Type[BasePlugin]):
        self._plugins[plugin_class.name] = plugin_class

    def load_from_directory(self, directory: Path):
        if not directory.exists():
            return

        for file in directory.glob("*.py"):
            if file.name.startswith("_"):
                continue

            spec = importlib.util.spec_from_file_location(file.stem, str(file))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin
                ):
                    self._plugins[attr.name] = attr

    def get(self, name: str) -> Type[BasePlugin]:
        if name not in self._plugins:
            available = ", ".join(self._plugins.keys())
            raise KeyError(f"Plugin '{name}' not found. Available: {available}")
        return self._plugins[name]

    def list_plugins(self) -> list:
        return [
            {
                "name": cls.name,
                "description": cls.description,
                "version": cls.version,
            }
            for cls in self._plugins.values()
        ]
