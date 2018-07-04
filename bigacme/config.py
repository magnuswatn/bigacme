"""Handles the configuration"""
import os
import logging
import configparser
from collections import namedtuple

logger = logging.getLogger(__name__)

CONFIG_FILE = "config/config.ini"
LOG_CONFIG_FILE = "config/logging.ini"
CONFIG_DIRS = ["config", "cert", "cert/backup"]


class ConfigError(Exception):
    """Superclass for all config exceptions."""

    pass


def check_configfiles():
    """Checks that the configuration files and folders are in place"""
    return (
        all(os.path.isdir(x) for x in CONFIG_DIRS)
        and os.path.isfile(CONFIG_FILE)
        and os.path.isfile(LOG_CONFIG_FILE)
    )


def read_configfile():
    """Reads the configfile and creates a config object"""
    configtp = namedtuple(
        "Config",
        [
            "lb_user",
            "lb_pwd",
            "lb1",
            "lb2",
            "lb_dg",
            "lb_dg_partition",
            "ca",
            "ca_proxy",
            "cm_account",
            "cm_renewal_days",
            "cm_delayed_days",
            "plugin",
        ],
    )
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if config.getboolean("Certificate Authority", "use proxy"):
        ca_proxy = config.get("Certificate Authority", "proxy")
    else:
        ca_proxy = False

    if config.getboolean("Load Balancer", "cluster"):
        bigip1 = config.get("Load Balancer", "host 1")
        bigip2 = config.get("Load Balancer", "host 2")
    else:
        bigip1 = config.get("Load Balancer", "host 1")
        bigip2 = None

    try:
        plugin_section = config.items("Plugin")
    except configparser.NoSectionError:
        plugin_section = None

    the_config = configtp(
        lb1=bigip1,
        lb2=bigip2,
        lb_user=config.get("Load Balancer", "username"),
        lb_pwd=config.get("Load Balancer", "password"),
        lb_dg=config.get("Load Balancer", "datagroup"),
        lb_dg_partition=config.get("Load Balancer", "datagroup partition"),
        ca=config.get("Certificate Authority", "directory url"),
        ca_proxy=ca_proxy,
        cm_account=config.get("Common", "account config"),
        cm_renewal_days=int(config.get("Common", "renewal days")),
        cm_delayed_days=int(config.get("Common", "delayed installation days")),
        plugin=plugin_section,
    )
    return the_config


def create_configfile():
    """Creates a default configfile"""
    config = configparser.ConfigParser()
    config.add_section("Common")
    config.set("Common", "renewal days", "20")
    config.set("Common", "delayed installation days", "5")
    config.set("Common", "account config", "./config/account.json")
    config.add_section("Load Balancer")
    config.set("Load Balancer", "cluster", "True")
    config.set("Load Balancer", "Host 1", "lb1.example.com")
    config.set("Load Balancer", "Host 2", "lb2.example.com")
    config.set("Load Balancer", "username", "admin")
    config.set("Load Balancer", "password", "password01")
    config.set("Load Balancer", "datagroup", "acme_responses_dg")
    config.set("Load Balancer", "datagroup partition", "Common")
    config.add_section("Certificate Authority")
    config.set(
        "Certificate Authority",
        "Directory URL",
        "https://acme-v02.api.letsencrypt.org/directory",
    )
    config.set("Certificate Authority", "use proxy", "False")
    config.set("Certificate Authority", "proxy", "http://proxy.example.com:8080")

    # As the config file contains password, we should be careful with permissions
    with os.fdopen(
        os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT, 0o660), "w"
    ) as config_file:
        config.write(config_file)


def create_logconfigfile(debug):
    """
    Creates a default log config file

    Normally we just use the root logger, but if debug is specified,
    we create a separate logger for bigacme,
    and stops it from propagate to the root logger.
    Otherwise it will be flooded with suds logging

    """
    config = configparser.ConfigParser()
    config.add_section("loggers")

    if debug:
        config.set("loggers", "keys", "root, bigacme")
    else:
        config.set("loggers", "keys", "root")

    config.add_section("handlers")
    config.set("handlers", "keys", "fileHandler")
    config.add_section("formatters")
    config.set("formatters", "keys", "fileFormatter")
    config.add_section("logger_root")
    config.set("logger_root", "level", "INFO")
    config.set("logger_root", "handlers", "fileHandler")

    if debug:
        config.add_section("logger_bigacme")
        config.set("logger_bigacme", "qualname", "bigacme")
        config.set("logger_bigacme", "level", "DEBUG")
        config.set("logger_bigacme", "handlers", "fileHandler")
        config.set("logger_bigacme", "propagate", "0")

    config.add_section("handler_fileHandler")
    config.set("handler_fileHandler", "class", "FileHandler")

    if debug:
        config.set("handler_fileHandler", "level", "DEBUG")
    else:
        config.set("handler_fileHandler", "level", "INFO")
    config.set("handler_fileHandler", "formatter", "fileFormatter")
    config.set("handler_fileHandler", "args", "('./log.log', 'a')")
    config.add_section("formatter_fileFormatter")
    config.set(
        "formatter_fileFormatter", "format", "%(asctime)s - %(levelname)s - %(message)s"
    )

    with open(LOG_CONFIG_FILE, "w") as config_file:
        config.write(config_file)
