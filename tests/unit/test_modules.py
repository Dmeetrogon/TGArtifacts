"""UT-047..056: Module system tests."""

import pytest

from tgartifacts.modules.base import BaseModule
from tgartifacts.modules import discover_modules


class ConcreteModule(BaseModule):
    @property
    def name(self): return "test-module"
    @property
    def description(self): return "A test module"
    @property
    def help_text(self): return "Test help"
    @property
    def requirements(self): return ["nonexistent_package_xyz>=99.0"]


class MinimalModule(BaseModule):
    @property
    def name(self): return "minimal"
    @property
    def description(self): return "Minimal module"
    @property
    def help_text(self): return "Minimal help"


class TestBaseModule:
    """UT-047..052."""

    def test_ut047_abstract_cannot_instantiate(self):
        """UT-047: BaseModule is abstract, can't instantiate directly."""
        with pytest.raises(TypeError):
            BaseModule()

    def test_ut048_concrete_has_name(self):
        """UT-048: Concrete module has name property."""
        m = ConcreteModule()
        assert m.name == "test-module"
        assert m.description == "A test module"

    def test_ut049_default_version(self):
        """UT-049: Default version is 0.1.0."""
        m = MinimalModule()
        assert m.version == '0.1.0'

    def test_ut050_default_dependencies_empty(self):
        """UT-050: Default dependencies is empty list."""
        m = MinimalModule()
        assert m.dependencies == []

    def test_ut051_check_requirements_missing(self):
        """UT-051: check_requirements returns missing packages."""
        m = ConcreteModule()
        missing = m.check_requirements()
        assert len(missing) >= 1
        assert any("nonexistent_package_xyz" in r for r in missing)

    def test_ut052_check_requirements_satisfied(self):
        """UT-052: check_requirements returns empty for installed packages."""
        m = MinimalModule()
        assert m.check_requirements() == []


class TestDiscoverModules:
    """UT-053..056."""

    def test_ut053_discover_returns_list(self):
        """UT-053: discover_modules returns a list."""
        modules = discover_modules()
        assert isinstance(modules, list)

    def test_ut054_known_modules_found(self):
        """UT-054: Expected built-in modules are discovered."""
        modules = discover_modules()
        names = {m['name'] for m in modules}
        assert 'info' in names
        assert 'export-session' in names

    def test_ut055_module_has_required_keys(self):
        """UT-055: Each module dict has required keys."""
        modules = discover_modules()
        required = {'name', 'description', 'version', 'deps', 'requirements', 'methods', 'package', 'instance'}
        for m in modules:
            assert required.issubset(m.keys()), f"Module {m.get('name')} missing keys"

    def test_ut056_no_duplicate_names(self):
        """UT-056: No two modules share the same name."""
        modules = discover_modules()
        names = [m['name'] for m in modules]
        assert len(names) == len(set(names))
