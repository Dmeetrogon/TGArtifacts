import importlib
import functools
import pkgutil
import click
from pathlib import Path


def discover_modules() -> list:
    """Scan modules/ subdirectories for installed modules."""
    found = []
    for importer, name, is_pkg in pkgutil.iter_modules(__path__):
        if not is_pkg or name.startswith('_'):
            continue
        try:
            mod = importlib.import_module(f'.{name}', __package__)
            instance = getattr(mod, 'module', None)
            if instance is not None:
                found.append({
                    'name': instance.name,
                    'description': instance.description,
                    'version': instance.version,
                    'deps': instance.dependencies,
                    'requirements': instance.requirements,
                    'methods': instance.available_methods,
                    'package': name,
                    'instance': instance,
                })
        except Exception:
            continue
    return found


def validate_dependencies(modules: list) -> None:
    """Warn if any module declares a dependency on a module that wasn't discovered."""
    known = {m['name'] for m in modules}
    for m in modules:
        for dep in m['deps']:
            if dep not in known:
                click.secho(
                    f"Warning: module '{m['name']}' depends on '{dep}', "
                    f"which was not found",
                    fg='yellow', err=True,
                )


def _wrap_with_requirements_check(cmd: click.Command, instance) -> None:
    """Wrap a click command's callback to check requirements before execution."""
    original = cmd.callback
    if original is None:
        return

    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        missing = instance.check_requirements()
        if missing:
            pkg_list = ', '.join(missing)
            raise click.ClickException(
                f"Module '{instance.name}' requires: {pkg_list}\n"
                f"Install with: pip install tgartifacts[{instance.name}]"
            )
        return original(*args, **kwargs)

    cmd.callback = wrapper


def register_modules(cli: click.Group) -> None:
    """Auto-discover modules and register their CLI commands."""
    modules = discover_modules()
    validate_dependencies(modules)

    instances = {m['package']: m['instance'] for m in modules}

    for _, name, is_pkg in pkgutil.iter_modules(__path__):
        if not is_pkg or name.startswith('_'):
            continue
        try:
            answer = importlib.import_module(f'.{name}.answer_cli', __package__)
            if hasattr(answer, 'command'):
                cmd = answer.command
                if cmd.name == 'command':
                    cmd.name = name.replace('_', '-')
                if name in instances:
                    instance = instances[name]
                    cmd.help = instance.help_text
                    _wrap_with_requirements_check(cmd, instance)
                cli.add_command(cmd)
        except Exception:
            continue
