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

def test_create_and_read_configfile():
    bigacme.config.create_configfile('./config/config.ini')
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
    bigacme.config.create_logconfigfile('./config/logging.ini')
    logging.config.fileConfig('./config/logging.ini')
