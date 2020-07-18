import os
import random
import string
import sys
import tempfile
from collections import namedtuple

import bigsuds
import OpenSSL
import pytest
from f5.bigip import ManagementRoot

import bigacme.lb


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
    return OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)


def _generate_password():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "".join(random.SystemRandom().choice(chars) for _ in range(32))


@pytest.fixture(scope="module")
def temp_partition(rest_lb):
    partition = rest_lb.tm.auth.partitions.partition.create(name="bigacmeTestPartition")
    yield "bigacmeTestPartition"
    partition.delete()


@pytest.fixture(scope="module")
def lb(opt_username, opt_password, opt_lb, opt_datagroup, opt_partition):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user=opt_username,
        lb_pwd=opt_password,
        lb1=opt_lb,
        lb2=None,
        lb_dg=opt_datagroup,
        lb_dg_partition=opt_partition,
    )
    return bigacme.lb.LoadBalancer.create_from_config(config)


@pytest.fixture(scope="module")
def rest_lb(opt_lb, opt_username, opt_password):
    return ManagementRoot(opt_lb, opt_username, opt_password, verify=True)


def test_send__and_remove_challenge(lb, rest_lb, opt_partition, opt_datagroup):
    lb.send_challenge("test.watn.no", "hei", "striiing")
    datag = rest_lb.tm.ltm.data_group.internals.internal.load(
        partition=opt_partition, name=opt_datagroup
    )
    assert {"data": "striiing", "name": "test.watn.no:hei"} in datag.records

    # Should not fail when already exists
    lb.send_challenge("test.watn.no", "hei", "striiing2")
    datag = rest_lb.tm.ltm.data_group.internals.internal.load(
        partition=opt_partition, name=opt_datagroup
    )
    assert {"data": "striiing2", "name": "test.watn.no:hei"} in datag.records

    lb.remove_challenge("test.watn.no", "hei")
    datag = rest_lb.tm.ltm.data_group.internals.internal.load(
        partition=opt_partition, name=opt_datagroup
    )
    if hasattr(datag, "records"):
        assert {"data": "striiing2", "name": "test.watn.no:hei"} not in datag.records


def test_get_csr(lb, rest_lb):
    pem_csr = _generate_csr("commonName", b"DNS:SAN")
    csr_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    csr_file.write(pem_csr)
    csr_file.seek(0)
    rest_lb.shared.file_transfer.uploads.upload_file(csr_file.name)

    csr_filename = os.path.basename(csr_file.name)
    csr = rest_lb.tm.sys.file.ssl_csrs.ssl_csr.create(
        name="/Common/test_get_csr",
        sourcePath="file:/var/config/rest/downloads/%s" % csr_filename,
    )
    pem_csr2 = lb.get_csr("Common", "test_get_csr")
    assert pem_csr.decode() == pem_csr2
    csr.delete()


def test_get_csr_not_existing(lb, rest_lb):
    with pytest.raises(bigacme.lb.NotFoundError):
        lb.get_csr("Common", "NotACsr")


def test_get_csr_not_existing_Partition(lb, rest_lb):
    with pytest.raises(bigacme.lb.PartitionNotFoundError):
        lb.get_csr("NotAPartition", "NotACsr")


def test_get_csr_no_access(
    rest_lb, opt_lb, temp_partition, opt_datagroup, opt_partition
):
    """Test that when a user does not have access to the partition,
    we correctly raise an AccessDeniedError.

    Create a partition and a user that does not have access to it, and try to retrieve
    a csr from the partition. This should fail with a AccessDeniedError.
    """
    password = _generate_password()

    partition_access = [{"role": "guest", "name": "Common"}]
    user = rest_lb.tm.auth.users.user.create(
        name="bigacmeTestUser",
        tmPartition="Common",
        password=password,
        partitionAccess=partition_access,
    )

    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="bigacmeTestUser",
        lb_pwd=password,
        lb1=opt_lb,
        lb2=None,
        lb_dg=opt_datagroup,
        lb_dg_partition=opt_partition,
    )
    bigip = bigacme.lb.LoadBalancer.create_from_config(config)

    with pytest.raises(bigacme.lb.AccessDeniedError):
        bigip.get_csr(temp_partition, "anyName")

    user.delete()


def test_upload_certificate(lb, opt_partition):
    cert = _generate_certificate(0, 9_999_999)
    lb.upload_certificate(opt_partition, "test_upload_certificate_certificate", [cert])
    # Should overwrite, so should not fail if uploaded again
    cert2 = _generate_certificate(0, 9_999_999)
    lb.upload_certificate(opt_partition, "test_upload_certificate_certificate", [cert2])


def test_upload_certificate_nonexisting_partition(lb):
    cert = _generate_certificate(0, 9_999_999)
    with pytest.raises(bigacme.lb.PartitionNotFoundError):
        lb.upload_certificate(
            "NotAPartition", "test_upload_certificate_certificate", [cert]
        )


def test_distinct_sessions(
    lb, rest_lb, temp_partition, opt_username, opt_password, opt_lb
):
    """
    Tests that bigacme uses it's own session, so that another API call with the
    same user won't mess with bigacmes session.
    """

    cert = _generate_certificate(0, 9_999_999)
    lb.upload_certificate(temp_partition, "test_distinct_sessions_certificate", [cert])
    rest_lb.tm.sys.crypto.certs.cert.load(
        partition=temp_partition, name="test_distinct_sessions_certificate.crt"
    ).delete()

    active_partition1 = lb.bigip.System.Session.get_active_folder()
    assert active_partition1 == f"/{temp_partition}"

    bigip = bigsuds.BIGIP(opt_lb, opt_username, opt_password, verify=True)
    bigip.System.Session.set_active_folder("/Common")

    active_partition2 = lb.bigip.System.Session.get_active_folder()
    assert active_partition1 == active_partition2
