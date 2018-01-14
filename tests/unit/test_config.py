import os
import re
import sys
import stat
import shutil
import tempfile
import fileinput
import logging.config
from collections import namedtuple

import pytest
import bigacme.config

def setup_module(module):
    temp_dir = tempfile.mkdtemp()
    os.chdir(temp_dir)
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        os.makedirs(folder)

def teardown_module(module):
    if '/tmp/' in os.getcwd():
        shutil.rmtree(os.getcwd())


def test_check_configfiles():
    assert not bigacme.config.check_configfiles()
    with open('./config/config.ini', 'a') as open_file:
        open_file.write('hei')
    with open('./config/logging.ini', 'a') as open_file:
        open_file.write('hei')
    assert bigacme.config.check_configfiles()
    os.rmdir('cert/backup')
    assert not bigacme.config.check_configfiles()
    os.remove('./config/config.ini')
    os.remove('./config/logging.ini')

def test_create_and_read_configfile():
    bigacme.config.create_configfile('./config/config.ini')
    assert oct(os.stat('./config/config.ini')[stat.ST_MODE]) == '0100660'

    config = bigacme.config.read_configfile('./config/config.ini')

    # the host 2 option should not be used if Cluster = False
    for line in fileinput.input('./config/config.ini', inplace=True):
        sys.stdout.write(re.sub('cluster = (True|False)', 'cluster = False', line).replace(
            'host 2 = lb2.example.com', ''))
    config = bigacme.config.read_configfile('./config/config.ini')
    assert config.lb2 is None

    # If use proxy = True, the proxy address should be read
    for line in fileinput.input('./config/config.ini', inplace=True):
        sys.stdout.write(re.sub('use proxy = (True|False)', 'use proxy = True', line))
    config = bigacme.config.read_configfile('./config/config.ini')
    assert config.ca_proxy == 'http://proxy.example.com:8080'

    # The proxy address should not be used if use proxy = False
    for line in fileinput.input('./config/config.ini', inplace=True):
        sys.stdout.write(re.sub('use proxy = (True|False)', 'use proxy = False', line).replace(
            'proxy = http://proxy.example.com:8080', ''))
    config = bigacme.config.read_configfile('./config/config.ini')
    assert not config.ca_proxy

    # The plugin config should be False by default
    assert not config.plugin

    # If there is a Plugin section, the whole should be returned as config.plugin
    plugin_config = "[Plugin]\noption1 = yes\noption2 = no"
    with open('./config/config.ini', 'a') as config_file:
        config_file.write(plugin_config)
    config = bigacme.config.read_configfile('./config/config.ini')
    assert len(config.plugin) == 2
    assert config.plugin[0][1] == "yes"
    assert config.plugin[1][1] == "no"

def test_create_account_key():
    configtp = namedtuple('Config', ['cm_key'])
    config = configtp(cm_key='./config/key.pem')
    bigacme.config.create_account_key(config)
    assert os.path.isfile(config.cm_key)
    assert oct(os.stat('./config/key.pem')[stat.ST_MODE]) == '0100440'
    with pytest.raises(bigacme.config.KeyAlreadyExistsError):
        bigacme.config.create_account_key(config)
    bigacme.config.delete_account_key(config)
    assert not os.path.isfile(config.cm_key)

def test_create_logconfigfile():
    """ Creates a normal logconfig file"""
    bigacme.config.create_logconfigfile('./config/logging.ini', False)
    logging.config.fileConfig('./config/logging.ini')
    # root logger should be INFO and the bigacme logger nothin, but should propagate
    assert logging.getLogger().level == 20
    assert logging.getLogger('bigacme').level == 0
    assert logging.getLogger('bigacme').propagate == 1

def test_create_logconfigfile_debug():
    """ Creates a debug logconfig file"""
    bigacme.config.create_logconfigfile('./config/logging.ini', True)
    logging.config.fileConfig('./config/logging.ini')
    # root logger should be INFO and the bigacme logger DEBUG and not propagate
    assert logging.getLogger().level == 20
    assert logging.getLogger('bigacme').level == 10
    assert logging.getLogger('bigacme').propagate == 0
