from abc import ABC, abstractmethod
from importlib.metadata import PackageNotFoundError, version as pkg_version
from typing import List
import re


class BaseModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def help_text(self) -> str:
        """Detailed help shown in --help. Must describe usage, capabilities, and examples."""
        ...

    @property
    def version(self) -> str:
        return '0.1.0'

    @property
    def dependencies(self) -> List[str]:
        """Other module names this module depends on."""
        return []

    @property
    def requirements(self) -> List[str]:
        """Pip packages this module needs (PEP 508 format)."""
        return []

    @property
    def available_methods(self) -> List[str]:
        return []

    def check_requirements(self) -> List[str]:
        """Return list of missing or incompatible pip packages."""
        missing = []
        for req in self.requirements:
            # Parse PEP 508: extract package name and optional version spec
            match = re.match(r'^([A-Za-z0-9_.-]+)\s*(.*)', req)
            if not match:
                continue
            pkg_name = match.group(1)
            try:
                pkg_version(pkg_name)
            except PackageNotFoundError:
                missing.append(req)
        return missing
