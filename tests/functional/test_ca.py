"""Functional tests for ca.py"""
import fileinput
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import namedtuple

import pytest

from bigacme import ca, config


def use_pebble(func):
    """Creates config folders, and returns the pebble process"""

    def pebble_wrapper(tmpdir, pebble, opt_username, opt_password, opt_lb):
        os.environ["REQUESTS_CA_BUNDLE"] = os.path.abspath(
            "tests/functional/pebble/pebble.minica.pem"
        )
        old_dir = tmpdir.chdir()
        for folder in config.CONFIG_DIRS:
            os.makedirs(folder)
        try:
            func(pebble)
        finally:
            old_dir.chdir()

    return pebble_wrapper


@use_pebble
def test_register_and_save_account(pebble):
    configtp = namedtuple("Config", ["cm_account", "ca", "ca_proxy"])
    config = configtp(
        cm_account="./config/account.json",
        ca="https://localhost:14000/dir",
        ca_proxy=None,
    )
    acme_ca = ca.CertificateAuthority.create_from_config(config)
    assert acme_ca.key is None
    assert acme_ca.kid is None

    acme_ca._create_account_key()
    acme_ca.register("hei@hei.no")

    assert acme_ca.key is not None
    assert acme_ca.kid is not None

    assert oct(os.stat("./config/account.json")[stat.ST_MODE]) == "0o100440"
    with pytest.raises(ca.AccountInfoExistsError):
        acme_ca._save_account()
    # TODO too specific
    assert b"GET /dir" in pebble.stdout.readline()
    assert b"HEAD /nonce-plz" in pebble.stdout.readline()
    assert b"POST /sign-me-up" in pebble.stdout.readline()
    assert b"There are now 1 accounts in memory" in pebble.stdout.readline()
