import json
import os
import pwd
import shutil
import tempfile
from collections import namedtuple
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import OpenSSL
import pytest

import bigacme.cert

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


def _generate_certificate(not_before, not_after):
    """Generates a certificate in a file for testing purposes"""
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(357)
    cert.get_subject().CN = "test"
    cert.set_issuer(cert.get_subject())
    cert.gmtime_adj_notBefore(not_before)
    cert.gmtime_adj_notAfter(not_after)
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode()


def _generate_csr(cn, san):
    """Generates a csr for testing purposes"""
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)
    req = OpenSSL.crypto.X509Req()
    if cn:
        req.get_subject().CN = cn
    if san:
        sn = [OpenSSL.crypto.X509Extension(b"subjectAltName", False, san)]
        req.add_extensions(sn)
    req.set_pubkey(key)
    req.sign(key, "sha256")
    return OpenSSL.crypto.dump_certificate_request(
        OpenSSL.crypto.FILETYPE_PEM, req
    ).decode()


def test_get_certs_that_need_action():
    configtp = namedtuple("Config", ["cm_renewal_days", "cm_delayed_days"])
    config = configtp(cm_renewal_days=12, cm_delayed_days=4)
    csr = _generate_csr("commonName", b"DNS:san1,DNS:san2")

    # certs to be renewed
    cert_tbr1 = bigacme.cert.Certificate.new(
        "Common", "cert_tbr1", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert_tbr1.cert = _generate_certificate(-90800, 4320)
    cert_tbr1.mark_as_installed()
    cert_tbr2 = bigacme.cert.Certificate.new(
        "Common", "cert_tbr2", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert_tbr2.cert = _generate_certificate(-9_320_000, 90800)
    cert_tbr2.mark_as_installed()

    # certs to be installed
    cert_tbi1 = bigacme.cert.Certificate.new(
        "Common", "cert_tbi1", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert_tbi1.cert = _generate_certificate(-995_700, 1_923_200)
    cert_tbi1.status = bigacme.cert.Status.TO_BE_INSTALLED
    cert_tbi1.save()

    cert_tbi2 = bigacme.cert.Certificate.new(
        "Common", "cert_tbi2", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert_tbi2.cert = _generate_certificate(-999_700, 9_123_200)
    cert_tbi2.status = bigacme.cert.Status.TO_BE_INSTALLED
    cert_tbi2.save()

    # cert that neither
    cert_tbnothin = bigacme.cert.Certificate.new(
        "Common", "cert_tbnothin", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert_tbnothin.cert = _generate_certificate(-29_123_200, 29_123_200)
    cert_tbnothin.mark_as_installed()

    # random file in folder
    with open("./cert/not_json.json", "w") as open_file:
        open_file.write("this is not json")
    tbr, tbi = bigacme.cert.get_certs_that_need_action(config)
    tbr_names = tbi_names = []
    for cert in tbr:
        tbr_names.append(cert.name)
    for cert in tbi:
        tbi_names.append(cert.name)
    assert "cert_tbr1" and "cert_tbr2" in tbr_names
    assert "cert_tbi1" and "cert_tbi2" and "cert_tbnothin" not in tbr_names
    assert "cert_tbi1" and "cert_tbi2" in tbi_names
    assert "cert_tbr1" and "cert_tbr2" and "cert_tbnothin" not in tbi_names


def test_cert_about_to_expire():
    """Tests if a certificate about to expires is detected"""
    cert = _generate_certificate(-10800, 432_000)
    not_after_str, _ = bigacme.cert._get_cert_dates(cert)
    assert bigacme.cert._check_if_cert_about_to_expire(not_after_str, 14)


def test_cert_not_about_to_expire():
    """Tests if a certificate not about to expire is not detected"""
    cert = _generate_certificate(-10800, 15_552_000)
    not_after_str, _ = bigacme.cert._get_cert_dates(cert)
    assert not bigacme.cert._check_if_cert_about_to_expire(not_after_str, 14)


def test_get_cert_dates():
    cert = _generate_certificate(-10800, 15_552_000)
    actual_nva, actual_nvb = bigacme.cert._get_cert_dates(cert)
    expected_nva = (datetime.today().utcnow() + timedelta(seconds=15_552_000)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    expected_nvb = (datetime.today().utcnow() + timedelta(seconds=-10800)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    assert actual_nva.isoformat() == expected_nva
    assert actual_nvb.isoformat() == expected_nvb


def test_delete_expired_backups():
    cert = _generate_certificate(-10800, 15_552_000)
    expired_cert = _generate_certificate(-10800, -10)
    with open("./cert/backup/cert", "w") as open_file:
        open_file.write(cert)
    with open("./cert/backup/expired_cert", "w") as open_file:
        open_file.write(expired_cert)
    with open("./cert/backup/not_a_cert", "w") as open_file:
        open_file.write("this is not a cert")
    bigacme.cert.delete_expired_backups()
    assert os.path.isfile("./cert/backup/cert")
    assert not os.path.isfile("./cert/backup/expired_cert")


def test_create_certificate():
    cert = bigacme.cert.Certificate.create("Partition", "Name")
    assert cert.partition == "Partition"
    assert cert.name == "Name"
    assert cert.status == bigacme.cert.Status.NEW
    assert str(cert.path) == "cert/%s_%s.json" % ("Partition", "Name")
    assert cert.validation_method == bigacme.cert.ValidationMethod.HTTP01


def test_new_certificate():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Partition", "test_new_certificate", csr, bigacme.cert.ValidationMethod.DNS01
    )
    assert cert.partition == "Partition"
    assert cert.name == "test_new_certificate"
    assert cert.csr == csr
    assert cert.validation_method == bigacme.cert.ValidationMethod.DNS01


def test_get_non_existing_cert():
    with pytest.raises(bigacme.cert.CertificateNotFoundError):
        bigacme.cert.Certificate.get("Common", "test_get_non_existing_cert")


def test_save_and_get():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Partition", "test_save_and_get", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.save()
    cert2 = bigacme.cert.Certificate.get("Partition", "test_save_and_get")
    assert cert.__dict__ == cert2.__dict__


def test_get_without_validation_method():
    """Tests that a json withouth validation method fallbacks to http-01"""
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Partition",
        "test_get_without_validation_method",
        csr,
        bigacme.cert.ValidationMethod.DNS01,
    )
    cert.save()
    with open(cert.path, "r+") as json_bytes:
        json_dict = json.loads(json_bytes.read())
        json_dict.pop("validation_method")
        json_bytes.seek(0)
        json_bytes.write(json.dumps(json_dict))
        json_bytes.truncate()
    cert2 = bigacme.cert.Certificate.get(
        "Partition", "test_get_without_validation_method"
    )
    assert cert2.validation_method == bigacme.cert.ValidationMethod.HTTP01


def test_save_and_delete():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_save_and_delete", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.save()
    assert os.path.isfile(cert.path)
    cert.delete()
    assert not os.path.isfile(cert.path)


def test_mark_as_installed():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_mark_as_installed", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.save()
    assert cert.status == bigacme.cert.Status.NEW
    with open(cert.path, "r") as json_bytes:
        assert json.loads(json_bytes.read())["status"] == "New"
    cert.mark_as_installed()
    assert cert.status == bigacme.cert.Status.INSTALLED
    with open(cert.path, "r") as json_bytes:
        assert json.loads(json_bytes.read())["status"] == "Installed"


def test_renew():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_renew", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    org_cert = _generate_certificate(0, 1_555_200)
    org_chain = _generate_certificate(0, 1_555_200)
    org_cert_and_chain = org_cert + org_chain
    cert.cert = org_cert_and_chain
    new_cert = _generate_certificate(0, 1_555_200)
    new_chain = _generate_certificate(0, 1_555_200)
    new_cert_and_chain = new_cert + new_chain
    cert.renew(new_cert_and_chain)
    assert os.path.isfile("./cert/backup/Common_test_renew.cer")
    assert cert.status == bigacme.cert.Status.TO_BE_INSTALLED


def test_up_for_installation():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_old_enough", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.cert = _generate_certificate(-1_980_000, 4_320_000)
    cert.status = bigacme.cert.Status.TO_BE_INSTALLED
    assert cert.up_for_installation(13)


def test_not_up_for_installation_not_old_enough():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_old_enough", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.cert = _generate_certificate(0, 4_320_000)
    cert.status = bigacme.cert.Status.TO_BE_INSTALLED
    assert not cert.up_for_installation(14)


def test_not_up_for_installation_wrong_status():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_old_enough", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.cert = _generate_certificate(-1_980_000, 4_320_000)
    cert.status = bigacme.cert.Status.INSTALLED
    assert not cert.up_for_installation(13)


def test_up_for_renewal():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_about_to_expire", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.cert = _generate_certificate(-10800, 432_000)
    assert cert.up_for_renewal(14)


def test_not_up_for_renewal():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common", "test_not_about_to_expire", csr, bigacme.cert.ValidationMethod.HTTP01
    )
    cert.cert = _generate_certificate(-10800, 432_000_000)
    assert not cert.up_for_renewal(14)


def test_save_cert_weird_error():
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common",
        "test_save_when_owned_by_another_user",
        csr,
        bigacme.cert.ValidationMethod.HTTP01,
    )
    cert.path = MagicMock()
    cert.path.write_text.side_effect = IOError
    with pytest.raises(IOError):
        cert.save()


def test_save_when_owned_by_another_user(opt_user):
    """
    If a certificate is issued by another user than the one who is running the renew job
    the cert file will be owned by the issuing user. This should not fail as long as we
    own the folder and are able to re-create the file.

    Here we create a csr as root and then change to a normal user and try to save it again
    """
    if os.geteuid() != 0:
        pytest.skip("Not running as root")
    csr = _generate_csr("common-name", b"DNS:san1,DNS:san2")
    cert = bigacme.cert.Certificate.new(
        "Common",
        "test_save_when_owned_by_another_user",
        csr,
        bigacme.cert.ValidationMethod.HTTP01,
    )
    cert.save()
    uid = pwd.getpwnam(opt_user).pw_uid
    os.chown(".", uid, -1)
    # The folders must be owned by the correct user
    for folder in FOLDERS:
        os.chown(folder, uid, -1)
    os.setuid(uid)
    cert.save()
    path = Path(cert.path)
    assert path.exists()
    assert path.owner() == opt_user
