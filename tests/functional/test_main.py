"""Functional tests for main.py"""
import datetime
import fileinput
import os
import re
import subprocess
import sys

import pytest

from bigacme import cert, config, version


def empty_dir(func):
    """Sets the working directory to an empty directory"""

    def tempdir_wrapper(tmpdir):
        old_dir = tmpdir.chdir()
        try:
            func()
        finally:
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
        try:
            func()
        finally:
            old_dir.chdir()

    return tempdir_wrapper


def existing_account(func):
    """Creates an dummy account file, to fool the "you must register first" check"""

    def account_wrapper():
        with open(config.ACCOUNT_FILE, "w") as open_file:
            open_file.write("dummy account file")
        func()

    return account_wrapper


def use_pebble(func):
    """Creates an config with pebble as the CA, and returns the pebble process"""

    def pebble_wrapper(tmpdir, pebble, opt_username, opt_password, opt_lb):
        os.environ["REQUESTS_CA_BUNDLE"] = os.path.abspath(
            "tests/functional/pebble/pebble.minica.pem"
        )
        old_dir = tmpdir.chdir()
        for folder in config.CONFIG_DIRS:
            os.makedirs(folder)
        config.create_configfile()
        config.create_logconfigfile(False)
        for line in fileinput.input("./config/config.ini", inplace=True):
            mod1 = re.sub(
                "directory .*", r"directory url = https://localhost:14000/dir", line
            )
            mod2 = re.sub("cluster = .*", "cluster = False", mod1)
            mod3 = re.sub("host 1 = .*", f"host 1 = {opt_lb}", mod2)
            mod4 = re.sub("username = .*", f"username = {opt_username}", mod3)
            mod5 = re.sub("password = .*", f"password = {opt_password}", mod4)
            sys.stdout.write(mod5)
        try:
            func(pebble)
        finally:
            old_dir.chdir()

    return pebble_wrapper


def test_version():
    """The 'bigacme version' command should output the version number (plus newline)"""
    output = subprocess.check_output(["bigacme", "version"]).decode().split("\n")[0]
    assert output == version.__version__


def test_invalid_names():
    """Invalid partition and csr name should be rejected"""
    commands = ["new", "remove", "revoke"]
    for command in commands:
        cmd = subprocess.Popen(
            ["bigacme", command, "møøø/\\/", "normal"], stderr=subprocess.PIPE
        )
        assert "The requested object name is invalid" in cmd.communicate()[1].decode()
        assert cmd.returncode == 2
        cmd = subprocess.Popen(
            ["bigacme", command, "normal", "+++//æø"], stderr=subprocess.PIPE
        )
        assert "The requested object name is invalid" in cmd.communicate()[1].decode()
        assert cmd.returncode == 2


def test_nonexisting_config_folder():
    """The cli should fail if you point it at a nonexisting config folder"""
    cmd = subprocess.Popen(
        ["bigacme", "--config-dir", "/not/a/folder", "config"], stderr=subprocess.PIPE
    )
    assert (
        cmd.communicate()[1].decode()
        == "Could not locate the specified configuration folder.\n"
    )
    assert cmd.returncode == 1


@empty_dir
def test_nonexisting_config_files():
    """The cli should fail if there is no config files in the config folder"""
    cmd = subprocess.Popen(["bigacme", "new", "Common", "test"], stderr=subprocess.PIPE)
    assert cmd.communicate()[1].decode() == (
        "Could not find the configuration files in the specified folder.\n"
    )
    assert cmd.returncode == 1


@empty_dir
def test_config_abort():
    """When we abort the config command, it should not do anything"""
    cmd = subprocess.Popen(
        ["bigacme", "config"], stdin=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output = cmd.communicate(input=b"no\n")
    assert output[1].decode() == "Aborted!\n"
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        assert not os.path.isdir(folder)


@empty_dir
def test_config():
    """The config command should create the nessecary folders"""
    cmd = subprocess.Popen(
        ["bigacme", "config"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    cmd.communicate(input=b"yes\n")
    folders = ["config", "cert", "cert/backup"]
    for folder in folders:
        assert os.path.isdir(folder)
    files = ["config/config.ini", "config/logging.ini"]
    for fil in files:
        assert os.path.isfile(fil)


@working_dir
@existing_account
def test_remove_nonexisting_cert():
    """We should give the user feedback if removing of a cert failed"""
    cmd = subprocess.Popen(
        ["bigacme", "remove", "Common", "notacert"], stderr=subprocess.PIPE
    )
    output = cmd.communicate()
    assert cmd.returncode is 2
    assert "The specified certificate was not found" in output[1].decode()


@working_dir
def test_recreate_config():
    """The config should gracefully fail if the folders exists"""
    cmd = subprocess.Popen(
        ["bigacme", "config"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    cmd.communicate(input=b"yes\n")
    assert cmd.returncode is 0


@working_dir
def test_recreate_config_with_debug():
    """The config should recreate the missing config files, with debug config"""
    os.rmdir("cert/backup")
    os.remove("./config/logging.ini")
    cmd = subprocess.Popen(
        ["bigacme", "config", "-debug"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    cmd.communicate(input=b"yes\n")
    assert os.path.isfile("./config/logging.ini")
    assert os.path.isdir("./cert/backup")
    with open("./config/logging.ini") as log_config_file:
        log_config = log_config_file.read()
    assert "DEBUG" in log_config


@working_dir
def test_get_cert_without_account():
    """requsting a new cert without an account should fail gracefully"""
    cmd = subprocess.Popen(
        ["bigacme", "new", "Common", "test"],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert "must register" in cmd.communicate()[1].decode()


@working_dir
def test_renew_without_account():
    """renewing without an account should fail gracefully"""
    cmd = subprocess.Popen(
        ["bigacme", "renew"], stdin=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert "must register" in cmd.communicate()[1].decode()


@working_dir
def test_revoke_without_account():
    """revoking a cert without an account should fail gracefully"""
    cmd = subprocess.Popen(
        ["bigacme", "revoke", "Common", "test"],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert "must register" in cmd.communicate()[1].decode()


@working_dir
@existing_account
def test_revoke_nonexistent_cert():
    """The user should immediately get an error if the cert does not exist"""
    cmd = subprocess.Popen(
        ["bigacme", "revoke", "Common", "notACert"],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert "The specified certificate was not found" in cmd.communicate()[1].decode()


def test_blank():
    """With no arguments some usage info should be printed"""
    cmd = subprocess.Popen(["bigacme"], stdout=subprocess.PIPE)
    assert "Usage" in cmd.communicate()[0].decode()


@working_dir
@existing_account
def test_list_no_certs():
    cmd = subprocess.Popen(["bigacme", "list"], stderr=subprocess.PIPE)
    assert "No certificates found" in cmd.communicate()[1].decode()


@working_dir
@existing_account
def test_list_all_certs():
    cert.Certificate.create("Common", "cert1").save()
    cert.Certificate.create("Common", "cert2").save()
    cert.Certificate.create("Common", "cert3").save()
    cert.Certificate.create("Partition1", "cert").save()
    cert.Certificate.create("Partition2", "cert").save()
    cmd = subprocess.Popen(["bigacme", "list"], stdout=subprocess.PIPE)
    output = cmd.communicate()[0].decode()
    # five certs plus headers and separators is ten
    assert len(output.split("\n")) == 10


@working_dir
@existing_account
def test_list_specific_partition():
    cert.Certificate.create("Common", "cert1").save()
    cert.Certificate.create("Common", "cert2").save()
    cert.Certificate.create("Common", "cert3").save()
    cert.Certificate.create("Partition1", "cert").save()
    cert.Certificate.create("Partition2", "cert").save()
    cmd = subprocess.Popen(["bigacme", "list", "Partition1"], stdout=subprocess.PIPE)
    output = cmd.communicate()[0].decode()
    # one certs plus headers and separators is six
    assert len(output.split("\n")) == 6


@use_pebble
def test_register_abort(pebble):
    """If user regrets, we should abort"""
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(input=b"no\n")
    assert output[1].decode() == "Aborted!\n"
    assert cmd.returncode == 1
    assert not os.path.isfile("config/account.json")


@use_pebble
def test_tos_no_agree(pebble):
    """If the user doesn\'t agree to the tos, we should abort"""
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(input=b"yes\nno\n")
    assert output[1].decode() == "Aborted!\n"
    assert cmd.returncode == 1
    assert not os.path.isfile("config/account.json")


@use_pebble
def test_register_wrong_email(pebble):
    """If user typed in the wrong email, we should abort"""
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(input=b"yes\nyes\nemail@example.com\nno\n")
    assert output[1].decode() == "Aborted!\n"
    assert cmd.returncode == 1
    assert not os.path.isfile("config/account.json")


@use_pebble
def test_revoke_abort(pebble):
    """If user regrets, we should abort"""
    cert.Certificate.create("Common", "cert").save()

    # we must register first
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cmd.communicate(input=b"yes\nyes\nemail@example.com\nyes\n")

    cmd = subprocess.Popen(
        ["bigacme", "revoke", "Common", "cert"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(input=b"revoke\n")  # note not caps
    assert output[1].decode() == "Aborted!\n"
    assert cmd.returncode == 1


@working_dir
@existing_account
def test_incomplete_config_files():
    """
    The CLI should fail if the config files are not complete
    and it should print what is wrong with the config
    """
    for line in fileinput.input("./config/config.ini", inplace=True):
        sys.stdout.write(re.sub("\\[Certificate Authority\\]", "[what]", line))
    cmd = subprocess.Popen(["bigacme", "new", "Common", "test"], stderr=subprocess.PIPE)
    stderr = cmd.communicate()[1]
    assert cmd.returncode == 1
    assert b"The configuration files was found, but was not complete" in stderr
    # should also say which section is missing
    assert b"Certificate Authority" in stderr


@use_pebble
def test_register_fails(pebble):
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(input=b"yes\nyes\nnotanemailatall\nyes\n")
    assert "The registration failed" in output[1].decode()
    assert cmd.returncode == 1
    assert not os.path.isfile("config/account.json")


@use_pebble
def test_test_sucessfull(pebble):
    cmd = subprocess.Popen(
        ["bigacme", "test"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate()
    assert "was successfull" in output[0].decode()
    assert cmd.returncode == 0


@use_pebble
def test_new_cert_from_nonexistent_partition(pebble):
    # we must register first
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cmd.communicate(input=b"yes\nyes\nemail@example.com\nyes\n")

    cmd = subprocess.Popen(
        ["bigacme", "new", "Cmmon", "testulf"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate()
    assert "The specified partition does not seem to exist" in output[1].decode()


@use_pebble
def test_new_cert_from_nonexistent_csr(pebble):
    # we must register first
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cmd.communicate(input=b"yes\nyes\nemail@example.com\nyes\n")

    cmd = subprocess.Popen(
        ["bigacme", "new", "Common", "notACert"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate()
    assert "Could not find the csr" in output[1].decode()


@use_pebble
def test_test_lb_fail(pebble):
    # Change the bigip host to localhost
    for line in fileinput.input("./config/config.ini", inplace=True):
        mod1 = re.sub("host 1 = .*", f"host 1 = localhost", line)
        sys.stdout.write(mod1)

    cmd = subprocess.Popen(
        ["bigacme", "test"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate()
    assert "Could not connect to the load balancer" in output[1].decode()


@use_pebble
def test_test_ca_fail(pebble):
    # Change the directory
    for line in fileinput.input("./config/config.ini", inplace=True):
        mod1 = re.sub(
            "directory .*", r"directory url = https://localhost:14001/dir", line
        )
        sys.stdout.write(mod1)
    cmd = subprocess.Popen(
        ["bigacme", "test"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate()
    assert "Could not connect to the CA" in output[1].decode()


@use_pebble
def test_issuance_flow(pebble):
    """
    Here we test the whole issuance flow -> issuance, renewal and revoking
    """
    register()
    register_again()
    get_new_cert()
    get_new_cert_that_fails()
    renew_cert()
    install_cert()
    revoke_cert()


def register():
    """Registeres an account with Pebble"""
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cmd.communicate(input=b"yes\nyes\nemail@example.com\nyes\n")
    assert cmd.returncode == 0
    assert os.path.isfile("config/account.json")


def register_again():
    """The user should immediately get an error if an account already exists"""
    cmd = subprocess.Popen(
        ["bigacme", "register"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate()
    assert "Account config already exists" in output[1].decode()


def get_new_cert():
    """Issues a new certificate from pebble"""
    # TODO: this requires the CSR to be on the bigip. Should we create one instead?
    cmd = subprocess.Popen(
        ["bigacme", "new", "Common", "get_new_cert_Pebble"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(timeout=300)
    assert "Done." in output[0].decode()
    assert cmd.returncode == 0


def get_new_cert_that_fails():
    """Tries to issue a new cert, but fails"""
    # TODO: this requires the CSR to be on the bigip. Should we create one instead?
    cmd = subprocess.Popen(
        ["bigacme", "new", "Common", "get_new_cert_that_fails_Pebble"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(timeout=300)

    assert (
        "Could not get a certificate from the CA"
        and "The CA could not verify the challenge"
        and "no such host"
    ) in output[1].decode()
    assert cmd.returncode != 0


def renew_cert():
    # We set the not after time to 10 days in the future. That should mark if for renewal
    certobj = cert.Certificate.get("Common", "get_new_cert_Pebble")
    new_expr_date = datetime.datetime.today().utcnow() + datetime.timedelta(days=10)
    certobj.not_after = new_expr_date.replace(microsecond=0)
    certobj.save()

    cmd = subprocess.Popen(
        ["bigacme", "renew"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cmd.communicate(timeout=300)

    with open("log.log", "r") as open_log:
        log_text = open_log.read()
    print(log_text)
    assert cmd.returncode == 0
    assert "Renewing cert" in log_text

    certobj = cert.Certificate.get("Common", "get_new_cert_Pebble")
    assert certobj.status == cert.Status.TO_BE_INSTALLED


def install_cert():
    # We set the not before before to 10 days in the past.
    # That should mark if for installation
    certobj = cert.Certificate.get("Common", "get_new_cert_Pebble")
    new_expr_date = datetime.datetime.today().utcnow() - datetime.timedelta(days=10)
    certobj.not_before = new_expr_date.replace(microsecond=0)
    certobj.save()

    cmd = subprocess.Popen(
        ["bigacme", "renew"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cmd.communicate(timeout=300)
    assert cmd.returncode == 0
    with open("log.log", "r") as open_log:
        log_text = open_log.read()
    assert "Installing cert" in log_text

    certobj = cert.Certificate.get("Common", "get_new_cert_Pebble")
    assert certobj.status == cert.Status.INSTALLED


def revoke_cert():
    cmd = subprocess.Popen(
        ["bigacme", "revoke", "Common", "get_new_cert_Pebble"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = cmd.communicate(input=b"REVOKE\n0\n")
    assert cmd.returncode == 0
    assert "revoked" in output[0].decode()
    with pytest.raises(cert.CertificateNotFoundError):
        cert.Certificate.get("Common", "get_new_cert_Pebble")
