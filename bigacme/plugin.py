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

    plugins = []
    for entry_point in iter_entry_points(group="bigacme.plugins"):
        plugins += [entry_point]

    if not plugins:
        raise NoPluginFoundError()

    if len(plugins) > 1:
        logger.warning("Several plugins found. This is not supported.")

    if not configuration.plugin:
        raise InvalidConfigError("No Plugin section in configuration file")

    plugin_config = dict()
    for param, value in configuration.plugin:
        plugin_config[param] = value

    plugin = plugins[0].load()

    if not issubclass(plugin, BigacmePlugin):
        raise PluginError("Plugin is not a valid bigacme plugin")

    logger.debug("Using plugin '%s'", plugin.name)

    return plugin(**plugin_config)


class BigacmePlugin:
    """This class represent a bigacme DNS plugin"""

    name = "generic bigacme plugin"

    def __init__(self, **kwargs):
        """
        Initialization of the plugin. It is expected to validate the configuration here.
        The configuration parameters from the config file is sendt as kwargs.

        :raises InvalidConfigError: If the configuration is not valid for the plugin.
        """

    def perform(self, domain: str, validation_name: str, validation: str):
        """
        Here the plugin must add the specified DNS record.

        :param str domain: The domain that is being validated, e.g. "example.com".
        :param str validation_name: The records that needs to be added.
            e.g. "_acme-challenge.example.com".
        :param str validation: The content/address of the DNS record.

        :raises PluginError: If the performing fails.
        """

    def finish_perform(self):
        """
        This is an optional method, where the plugin can finish up the performing.
        E.g. publish the zone files to the DNS servers or the like.

        :raises PluginError: If the performing fails.
        """

    def cleanup(self, domain: str, validation_name: str, validation: str):
        """
        Here the plugin can clean up after performing.
        This will normally be to remove the added records.

        :param str domain: The domain that is being validated, e.g. "example.com".
        :param str validation_name: The records that needs to be cleaned.
            e.g. "_acme-challenge.example.com".
        :param str validation: The content/address of the DNS record.

        :raises PluginError: If the cleanup fails.
        """

    def finish_cleanup(self):
        """
        This is an optional method, where the plugin can finish up the cleanup.
        E.g. publish the zone files to the DNS servers or the like.

        :raises PluginError: If the cleanup fails.
        """
