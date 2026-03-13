from ..base import BaseModule


class PluginModule(BaseModule):
    @property
    def name(self):
        return 'plugin'

    @property
    def description(self):
        return 'Run a plugin on tdata directory'

    @property
    def help_text(self):
        return (
            "Run a plugin on a tdata directory.\n"
            "\n"
            "Loads the specified plugin by name, parses the tdata directory, "
            "and executes the plugin with full account and cache context.\n"
            "\n"
            "Use 'tgartifacts list-plugins' to see available plugin names.\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts plugin my-plugin /path/to/tdata\n"
            "  tgartifacts plugin export-media /path/to/tdata -o ./output\n"
            "  tgartifacts plugin custom /path/to/tdata --plugins-dir ./my-plugins"
        )

    @property
    def available_methods(self):
        return ['plugin']


module = PluginModule()
