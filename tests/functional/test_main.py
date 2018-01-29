"""Functional tests for main.py"""
import re
import os
import sys
import shutil
import tempfile
import fileinput
import subprocess

from bigacme import version

def setup_module(module):
    temp_dir = tempfile.mkdtemp()
    os.chdir(temp_dir)

def teardown_module(module):
    if '/tmp/' in os.getcwd():
        shutil.rmtree(os.getcwd())

def test_version():
    """The 'bigacme version' command should output the verison number (plus newline)"""
    output = subprocess.check_output(['bigacme', 'version']).split('\n')[0]
    assert output == version.__version__

def test_nonexisting_config_folder():
    """The cli should fail if you point it at a nonexisting config folder"""
    cmd = subprocess.Popen(['bigacme', '--config-dir', '/not/a/folder', 'config'],
                           stderr=subprocess.PIPE)
    assert cmd.communicate()[1] == 'Could not locate the specified configuration folder\n'
    assert cmd.returncode == 1

def test_nonexisting_config_files():
    """The cli should fail if there is no config files in the config folder"""
    cmd = subprocess.Popen(['bigacme', 'new', 'Common', 'test'], stderr=subprocess.PIPE)
    assert cmd.communicate()[1] == ('Could not find the configuration files in the '
                                    'specified folder\n')
    assert cmd.returncode == 1

def test_config_abort():
    """When we abort the config command, it should not do anything"""
    cmd = subprocess.Popen(['bigacme', 'config'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input='no\n')
    assert output[1] == 'User did not want to continue. Exiting\n'
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        assert not os.path.isdir(folder)

def test_config():
    """The config command should create the nessecary folders"""
    cmd = subprocess.Popen(['bigacme', 'config'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.communicate(input='yes\n')
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        assert os.path.isdir(folder)
    files = ["config/config.ini", "config/logging.ini"]
    for fil in files:
        assert os.path.isfile(fil)

def test_recreate_config():
    """The config should gracefully fail if the folders exists"""
    cmd = subprocess.Popen(['bigacme', 'config'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.communicate(input='yes\n')
    assert cmd.returncode is 0

def test_recreate_config_with_debug():
    """The config should recreate the missing config files, with debug config"""
    os.rmdir('cert/backup')
    os.remove('./config/logging.ini')
    cmd = subprocess.Popen(['bigacme', 'config', '-debug'],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cmd.communicate(input='yes\n')
    assert os.path.isfile('./config/logging.ini')
    assert os.path.isdir('./cert/backup')
    with open('./config/logging.ini') as log_config_file:
        log_config = log_config_file.read()
    assert 'DEBUG' in log_config

def test_register_abort():
    """If user regrets, we should abort"""
    cmd = subprocess.Popen(['bigacme', 'register'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input='no\n')
    assert output[1] == 'User did not want to continue. Exiting\n'
    assert cmd.returncode == 1
    assert not os.path.isfile('/config/key.pem')

def test_register_wrong_email():
    """If user typed in the wrong email, we should abort"""
    cmd = subprocess.Popen(['bigacme', 'register'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input='yes\nemail@example.com\nno\n')
    assert output[1] == 'Wrong mail. Exiting\n'
    assert cmd.returncode == 1
    assert not os.path.isfile('/config/key.pem')

def test_revoke_abort():
    """If user regrets, we should abort"""
    cmd = subprocess.Popen(['bigacme', 'revoke', 'Common', 'cert'], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = cmd.communicate(input='revoke\n') # note not caps
    assert output[1] == 'Exiting...\n'
    assert cmd.returncode == 1

def test_incomplete_config_files():
    """
    The CLI should fail if the config files are not complete
    and it should print what is wrong with the config
    """
    for line in fileinput.input('./config/config.ini', inplace=True):
        sys.stdout.write(re.sub('[Certificate Authority]', '[what]', line))
    cmd = subprocess.Popen(['bigacme', 'new', 'Common', 'test'], stderr=subprocess.PIPE)
    stderr = cmd.communicate()[1]
    assert cmd.returncode == 1
    assert 'The configuration files was found, but was not complete.' in stderr
    # should also say which section is missing
    assert 'Certificate Authority' in stderr
