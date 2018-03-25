"""Functional tests for main.py"""
import re
import os
import sys
import fileinput
import subprocess

import pytest

from bigacme import cert
from bigacme import version
from bigacme import config

def empty_dir(func):
    """Sets the working directory to an empty directory"""
    def tempdir_wrapper(tmpdir):
        old_dir = tmpdir.chdir()
        func()
        old_dir.chdir()
    return tempdir_wrapper

def working_dir(func):
    """Sets the working directory to an directory with config files"""
    def tempdir_wrapper(tmpdir):
        old_dir = tmpdir.chdir()
        for folder in config.CONFIG_DIRS:
            os.makedirs(folder)
        config.create_configfile()
        config.create_logconfigfile(False)
        func()
        old_dir.chdir()
    return tempdir_wrapper

def use_pebble(func):
    """Creates an config with pebble as the CA, and returns the pebble process"""
    def tempdir_wrapper(tmpdir, pebble):
        os.environ['REQUESTS_CA_BUNDLE'] = os.path.abspath('tests/functional/pebble/pebble.minica.pem')
        old_dir = tmpdir.chdir()
        for folder in config.CONFIG_DIRS:
            os.makedirs(folder)
        config.create_configfile()
        config.create_logconfigfile(False)
        for line in fileinput.input('./config/config.ini', inplace=True):
            sys.stdout.write(re.sub('directory url = .*',
                                    r'directory url = https://localhost:14000/dir', line))
        func(pebble)
        old_dir.chdir()
    return tempdir_wrapper

@pytest.fixture(scope='session')
def pebble():
    pebble_proc = subprocess.Popen(['tests/functional/pebble/pebble', '-config',
                                    'tests/functional/pebble/pebble-config.json'],
                                   stdout=subprocess.PIPE)

    while b'Pebble running' not in pebble_proc.stdout.readline():
        pebble_proc.poll()
        if pebble_proc.returncode is not None:
            raise Exception('Pebble failed to start')
    yield pebble_proc
    pebble_proc.kill()


def test_version():
    """The 'bigacme version' command should output the verison number (plus newline)"""
    output = subprocess.check_output(['bigacme', 'version']).decode().split('\n')[0]
    assert output == version.__version__

def test_nonexisting_config_folder():
    """The cli should fail if you point it at a nonexisting config folder"""
    cmd = subprocess.Popen(['bigacme', '--config-dir', '/not/a/folder', 'config'],
                           stderr=subprocess.PIPE)
    assert cmd.communicate()[1].decode() == 'Could not locate the specified configuration folder\n'
    assert cmd.returncode == 1

@empty_dir
def test_nonexisting_config_files():
    """The cli should fail if there is no config files in the config folder"""
    cmd = subprocess.Popen(['bigacme', 'new', 'Common', 'test'], stderr=subprocess.PIPE)
    assert cmd.communicate()[1].decode() == ('Could not find the configuration files in the '
                                             'specified folder\n')
    assert cmd.returncode == 1

@empty_dir
def test_config_abort():
    """When we abort the config command, it should not do anything"""
    cmd = subprocess.Popen(['bigacme', 'config'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input=b'no\n')
    assert output[1].decode() == 'User did not want to continue. Exiting\n'
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        assert not os.path.isdir(folder)

@empty_dir
def test_config():
    """The config command should create the nessecary folders"""
    cmd = subprocess.Popen(['bigacme', 'config'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.communicate(input=b'yes\n')
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        assert os.path.isdir(folder)
    files = ["config/config.ini", "config/logging.ini"]
    for fil in files:
        assert os.path.isfile(fil)

@working_dir
def test_recreate_config():
    """The config should gracefully fail if the folders exists"""
    cmd = subprocess.Popen(['bigacme', 'config'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.communicate(input=b'yes\n')
    assert cmd.returncode is 0

@working_dir
def test_recreate_config_with_debug():
    """The config should recreate the missing config files, with debug config"""
    os.rmdir('cert/backup')
    os.remove('./config/logging.ini')
    cmd = subprocess.Popen(['bigacme', 'config', '-debug'],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.communicate(input=b'yes\n')
    assert os.path.isfile('./config/logging.ini')
    assert os.path.isdir('./cert/backup')
    with open('./config/logging.ini') as log_config_file:
        log_config = log_config_file.read()
    assert 'DEBUG' in log_config

def test_blank():
    """With no arguments some usage info should be printed"""
    cmd = subprocess.Popen(['bigacme'], stderr=subprocess.PIPE)
    assert 'usage' in  cmd.communicate()[1].decode()

# TODO: These tests now cause requests against Let's Encrypt. Should use pebble instead

@working_dir
def test_register_abort():
    """If user regrets, we should abort"""
    cmd = subprocess.Popen(['bigacme', 'register'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input=b'no\n')
    assert output[1].decode() == 'OK. Bye bye.\n'
    assert cmd.returncode == 1
    assert not os.path.isfile('config/account.json')

@working_dir
def test_tos_no_agree():
    """If the user doesn\'t agree to the tos, we should abort"""
    cmd = subprocess.Popen(['bigacme', 'register'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input=b'yes\nno\n')
    assert output[1].decode() == 'You must agree to the terms of service to register.\n'
    assert cmd.returncode == 1
    assert not os.path.isfile('config/account.json')

@working_dir
def test_register_wrong_email():
    """If user typed in the wrong email, we should abort"""
    cmd = subprocess.Popen(['bigacme', 'register'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input=b'yes\nyes\nemail@example.com\nno\n')
    assert output[1].decode() == 'Wrong mail. Exiting\n'
    assert cmd.returncode == 1
    assert not os.path.isfile('config/account.json')

@working_dir
def test_revoke_abort():
    """If user regrets, we should abort"""
    cert.Certificate('Common', 'cert').save()
    cmd = subprocess.Popen(['bigacme', 'revoke', 'Common', 'cert'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input=b'revoke\n') # note not caps
    assert output[1].decode() == 'Exiting...\n'
    assert cmd.returncode == 1

@working_dir
def test_incomplete_config_files():
    """
    The CLI should fail if the config files are not complete
    and it should print what is wrong with the config
    """
    for line in fileinput.input('./config/config.ini', inplace=True):
        sys.stdout.write(re.sub('\[Certificate Authority\]', '[what]', line))
    cmd = subprocess.Popen(['bigacme', 'new', 'Common', 'test'], stderr=subprocess.PIPE)
    stderr = cmd.communicate()[1]
    assert cmd.returncode == 1
    assert b'The configuration files was found, but was not complete.' in stderr
    # should also say which section is missing
    assert b'Certificate Authority' in stderr

@use_pebble
def test_register(pebble):
    cmd = subprocess.Popen(['bigacme', 'register'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd.communicate(input=b'yes\nyes\nemail@example.com\nyes\n')
    assert cmd.returncode == 0
    assert os.path.isfile('config/account.json')
