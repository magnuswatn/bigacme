"""Tests for plugin.py"""
from collections import namedtuple
from unittest import mock

import pytest

import bigacme.plugin


def _generate_dummy_config():
    """Generates a dummy config for a plugin"""
    configtp = namedtuple("Config", ["plugin"])
    config = configtp(plugin=([("hei", "sann"), ("hade", "bra")]))
    return config


def test_get_plugin_missing_config():
    configtp = namedtuple("Config", ["plugin"])
    config = configtp(plugin=None)

    class BigacmePlugin(bigacme.plugin.BigacmePlugin):
        name = "A correct plugin"

        def __init__(self, **kwargs):
            self.kwargs = kwargs

    registered_plugin = mock.MagicMock()
    registered_plugin.load.return_value = BigacmePlugin

    mock_entry_points = mock.MagicMock(return_value=[registered_plugin])

    with mock.patch("bigacme.plugin.iter_entry_points", mock_entry_points):
        with pytest.raises(bigacme.plugin.InvalidConfigError):
            bigacme.plugin.get_plugin(config)


def test_get_plugin_no_plugin():
    with pytest.raises(bigacme.plugin.NoPluginFoundError):
        bigacme.plugin.get_plugin(_generate_dummy_config())


def test_load_plugin():
    """
    Tests that loading plugins work.
    We should load the plugin with the kwargs from the config,
    and log a debug message that we did
    """

    class BigacmePlugin(bigacme.plugin.BigacmePlugin):
        name = "A correct plugin"

        def __init__(self, **kwargs):
            self.kwargs = kwargs

    registered_plugin = mock.MagicMock()
    registered_plugin.load.return_value = BigacmePlugin

    mock_logger = mock.MagicMock()

    mock_entry_points = mock.MagicMock(return_value=[registered_plugin])

    with mock.patch("bigacme.plugin.iter_entry_points", mock_entry_points), mock.patch(
        "bigacme.plugin.logger", mock_logger
    ):

        plugin = bigacme.plugin.get_plugin(_generate_dummy_config())

        assert plugin.kwargs == {"hei": "sann", "hade": "bra"}
        mock_logger.debug.assert_called_once_with(
            "Using plugin '%s'", "A correct plugin"
        )


def test_load_plugin_wrong_type():
    """We should raise a PluginError if the plugin is not a correct plugin"""

    class WrongTypePlugin(object):
        pass

    registered_plugin = mock.MagicMock()
    registered_plugin.load.return_value = WrongTypePlugin

    mock_entry_points = mock.MagicMock(return_value=[registered_plugin])

    with mock.patch("bigacme.plugin.iter_entry_points", mock_entry_points):
        with pytest.raises(bigacme.plugin.PluginError) as excinfo:
            bigacme.plugin.get_plugin(_generate_dummy_config())
        assert "Plugin is not a valid bigacme plugin" in str(excinfo.value)


def test_load_several_plugins():
    """
    If there are several plugins, we should load the first, and log an warning
    """

    class BigacmePlugin1(bigacme.plugin.BigacmePlugin):
        pass

    class BigacmePlugin2(bigacme.plugin.BigacmePlugin):
        pass

    registered_plugin1 = mock.MagicMock()
    registered_plugin1.load.return_value = BigacmePlugin1
    registered_plugin2 = mock.MagicMock()
    registered_plugin2.load.return_value = BigacmePlugin2

    mock_logger = mock.MagicMock()

    mock_entry_points = mock.MagicMock(
        return_value=[registered_plugin1, registered_plugin2]
    )
    with mock.patch("bigacme.plugin.iter_entry_points", mock_entry_points), mock.patch(
        "bigacme.plugin.logger", mock_logger
    ):
        plugin = bigacme.plugin.get_plugin(_generate_dummy_config())

        mock_logger.warning.assert_called_once_with(
            "Several plugins found. This is not supported."
        )
        assert isinstance(plugin, BigacmePlugin1)
