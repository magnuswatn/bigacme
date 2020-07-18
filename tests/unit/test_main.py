import json
import os
import shutil
import tempfile

import pytest

import bigacme.cert
import bigacme.main

ORG_CWD = os.getcwd()

FOLDERS = ["config", "cert", "cert/backup"]


def setup_module(module):
    temp_dir = tempfile.mkdtemp()
    os.chdir(temp_dir)
    for folder in FOLDERS:
        os.makedirs(folder)


def teardown_module(module):
    if "/tmp/" in os.getcwd():
        shutil.rmtree(os.getcwd())
    os.chdir(ORG_CWD)


def _create_certificates(certificates):
    for cert in certificates:
        certobj = bigacme.cert.Certificate.new(
            cert[0], cert[1], "csr", bigacme.cert.ValidationMethod.HTTP01
        )
        certobj.save()


def test_partition_completer_completion():
    certificates = [
        ("Common", "Cert1"),
        ("Partition1", "Cert2"),
        ("Partition1", "Cert3"),
        ("Common", "Cert4"),
        ("Partition2", "Cert5"),
    ]
    _create_certificates(certificates)
    common_complete = bigacme.main.partition_completer(None, None, "Co")
    assert common_complete == ["Common"]
    partitionx_complete = bigacme.main.partition_completer(None, None, "Part")
    assert partitionx_complete == ["Partition1", "Partition2"]


def test_partition_completer_exceptions():
    """An error should not throw a exception, but silently continue"""

    cert = bigacme.cert.Certificate.new(
        "Common", "what", "csr", bigacme.cert.ValidationMethod.HTTP01
    )
    cert.save()

    with open(cert.path, "r+") as json_bytes:
        json_dict = json.loads(json_bytes.read())
        json_dict.pop("name")
        json_bytes.seek(0)
        json_bytes.write(json.dumps(json_dict))
        json_bytes.truncate()
    completetion = bigacme.main.partition_completer(None, None, "Co")
    assert completetion == []
    cert.delete()


def test_csrname_completer_completion():
    certificates = [
        ("Common", "Cert1"),
        ("Partition1", "Cert2"),
        ("Partition1", "Cert3"),
        ("Common", "Cert4"),
        ("Partition2", "Cert5"),
        ("Common", "SomethingCompletelyDifferent"),
    ]
    _create_certificates(certificates)
    cert_complete = bigacme.main.csrname_completer(
        None, ["bigacme", "Partition1"], "Cer"
    )
    assert cert_complete == ["Cert2", "Cert3"]
    different_complete = bigacme.main.csrname_completer(
        None, ["bigacme", "Common"], "Some"
    )
    assert different_complete == ["SomethingCompletelyDifferent"]


def test_csrname_completer_exceptions():
    """An error should not throw a exception, but silently continue"""

    cert = bigacme.cert.Certificate.new(
        "Common", "what", "csr", bigacme.cert.ValidationMethod.HTTP01
    )
    cert.save()

    with open(cert.path, "r+") as json_bytes:
        json_dict = json.loads(json_bytes.read())
        json_dict.pop("name")
        json_bytes.seek(0)
        json_bytes.write(json.dumps(json_dict))
        json_bytes.truncate()

    completetion = bigacme.main.csrname_completer(None, ["bigacme", "Common"], "Some")
    assert completetion == []
    cert.delete()
