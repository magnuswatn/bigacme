"""Functions that interacts with DNS plugins"""
import logging
from pkg_resources import iter_entry_points

class PluginError(Exception):
    """Superclass for all plugin exceptions."""
    pass
class InvalidConfigError(PluginError):
    """Raised when the plugin configuration does not match the plugin"""
    pass
class NoPluginFoundError(PluginError):
    """Raised when no plugin was found"""
    pass

logger = logging.getLogger(__name__)

def get_plugin(configuration):
    """Discovers, and returns, the installed plugin"""

    if not configuration.plugin:
        raise InvalidConfigError("No Plugin section in configuration file")

    plugins = []
    for entry_point in iter_entry_points(group='bigacme.plugins'):
        plugins += [entry_point]

    if len(plugins) > 1:
        logger.warning("Several plugins found. This is not supported.")

    if plugins:
        plugin = plugins[0].load()
        return plugin(configuration.plugin)
    else:
        raise NoPluginFoundError
