import importlib.util
import os
import stat
import sys
from pathlib import Path
from typing import Dict, Type

import click

from .base import BasePlugin


class PluginManager:
    def __init__(self):
        self._plugins: Dict[str, Type[BasePlugin]] = {}

    @property
    def plugins(self) -> Dict[str, Type[BasePlugin]]:
        return dict(self._plugins)

    def register(self, plugin_class: Type[BasePlugin]):
        self._plugins[plugin_class.name] = plugin_class

    def _register_from_module(self, module):
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BasePlugin)
                and attr is not BasePlugin
            ):
                self._plugins[attr.name] = attr

    @staticmethod
    def _check_directory_permissions(directory: Path) -> None:
        if os.name == 'nt':
            return
        try:
            st = directory.stat()
            mode = st.st_mode
            if bool(mode & stat.S_IWGRP) or bool(mode & stat.S_IWOTH):
                raise PermissionError(
                    f"Plugin directory {directory} is writable by group/others "
                    f"(permissions: {oct(mode)[-3:]}). "
                    f"Fix: chmod 755 {directory}"
                )
            if st.st_uid != os.getuid():
                raise PermissionError(
                    f"Plugin directory {directory} is not owned by current user "
                    f"(owner uid: {st.st_uid}, current uid: {os.getuid()}). "
                )
        except OSError as e:
            raise PermissionError(f"Cannot stat plugin directory {directory}: {e}")

    def load_from_directory(self, directory: Path, trusted: bool = False):
        if not directory.exists():
            return

        if not trusted:
            self._check_directory_permissions(directory)

        _skip = {"__init__.py", "base.py", "manager.py"}
        for file in directory.glob("*.py"):
            if file.name.startswith("_") or file.name in _skip:
                continue
            spec = importlib.util.spec_from_file_location(file.stem, str(file))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._register_from_module(module)

        for subdir in sorted(directory.iterdir()):
            if not subdir.is_dir() or subdir.name.startswith("_"):
                continue
            init_file = subdir / "__init__.py"
            if not init_file.exists():
                continue
            module_name = f"_plugin_{subdir.name}"
            spec = importlib.util.spec_from_file_location(
                module_name, str(init_file),
                submodule_search_locations=[str(subdir)],
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            self._register_from_module(module)

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
