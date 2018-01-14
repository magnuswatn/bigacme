"""Tests for plugin.py"""
from collections import namedtuple
import pytest
import bigacme.plugin

def test_get_plugin_missing_config():
    configtp = namedtuple("Config", ["plugin"])
    config = configtp(plugin=None)
    with pytest.raises(bigacme.plugin.InvalidConfigError):
        bigacme.plugin.get_plugin(config)
