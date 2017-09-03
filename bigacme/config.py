"""Handles the configuration"""
import os
import logging
import ConfigParser
from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from acme import jose

logger = logging.getLogger(__name__)

class ConfigError(Exception):
    """Superclass for all config exceptions."""
    pass
class KeyAlreadyExistsError(ConfigError):
    """Raised when the account key file already exists."""
    pass

def check_configfiles():
    """Checks that the configuration files and folders are in place"""
    return (os.path.exists('./config/config.ini') and os.path.exists('./config/logging.ini') and
            os.path.exists('./cert') and os.path.exists('./cert/backup'))

def read_configfile(filename):
    """Reads the configfile and creates a config object"""
    configtp = namedtuple("Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition",
                                     "ca", "ca_proxy", "cm_chain", "cm_key", "cm_renewal_days",
                                     "cm_delayed_days", "plugin"])
    config = ConfigParser.ConfigParser()
    config.read(filename)
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
        plugin_section = config.items('Plugin')
    except ConfigParser.NoSectionError:
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
        cm_chain=config.getboolean("Common", "include chain"),
        cm_key=config.get("Common", "account key"),
        cm_renewal_days=int(config.get("Common", "renewal days")),
        cm_delayed_days=int(config.get("Common", "delayed installation days")),
        plugin=plugin_section)
    return the_config

def create_configfile(filename):
    """Creates a default configfile"""
    config = ConfigParser.ConfigParser()
    config.add_section('Common')
    config.set('Common', 'renewal days', 20)
    config.set('Common', 'delayed installation days', 5)
    config.set('Common', 'include chain', True)
    config.set('Common', 'account key', './config/key.pem')
    config.add_section('Load Balancer')
    config.set('Load Balancer', 'cluster', True)
    config.set('Load Balancer', 'Host 1', 'lb1.example.com')
    config.set('Load Balancer', 'Host 2', 'lb2.example.com')
    config.set('Load Balancer', 'username', 'admin')
    config.set('Load Balancer', 'password', 'password01')
    config.set('Load Balancer', 'datagroup', 'acme_responses_dg')
    config.set('Load Balancer', 'datagroup partition', 'Common')
    config.add_section('Certificate Authority')
    config.set('Certificate Authority', 'Directory URL',
               'https://acme-v01.api.letsencrypt.org/directory')
    config.set('Certificate Authority', 'use proxy', False)
    config.set('Certificate Authority', 'proxy',
               'http://proxy.example.com:8080')

    # As the config file contains password, we should be careful with permissions
    with os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, 0o660), 'w') as config_file:
        config.write(config_file)


def create_logconfigfile(filename):
    """Creates a default log config file"""
    config = ConfigParser.ConfigParser()
    config.add_section('loggers')
    config.set('loggers', 'keys', 'root')
    config.add_section('handlers')
    config.set('handlers', 'keys', 'fileHandler')
    config.add_section('formatters')
    config.set('formatters', 'keys', 'fileFormatter')
    config.add_section('logger_root')
    config.set('logger_root', 'level', 'INFO')
    config.set('logger_root', 'handlers', 'fileHandler')
    config.add_section('handler_fileHandler')
    config.set('handler_fileHandler', 'class', 'FileHandler')
    config.set('handler_fileHandler', 'level', 'INFO')
    config.set('handler_fileHandler', 'formatter', 'fileFormatter')
    config.set('handler_fileHandler', 'args', "('./log.log', 'a')")
    config.add_section('formatter_fileFormatter')
    config.set('formatter_fileFormatter', 'format', '%(asctime)s - %(levelname)s - %(message)s')

    with open(filename, 'w') as config_file:
        config.write(config_file)

def create_account_key(configuration):
    """Creates an account key and returns it"""
    # Checking if the specified key file already exists
    if os.path.exists(configuration.cm_key):
        raise KeyAlreadyExistsError("Key file already exists")
    else:
        logger.debug("The key file does not exist. All good.")

    logger.info("Generating private key")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    logging.info('Saving private key to: %s', configuration.cm_key)

    # Saving private key to file - we must be careful with the permissions
    with os.fdopen(os.open(configuration.cm_key, os.O_WRONLY | os.O_CREAT, 0o440), 'w') as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            ))

def delete_account_key(configuration):
    """Deletes the account key from disk"""
    os.remove(configuration.cm_key)
