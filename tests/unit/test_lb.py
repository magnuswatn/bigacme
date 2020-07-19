from collections import namedtuple
from unittest import mock

import pytest
from bigsuds import ConnectionError, ServerError

import bigacme.lb


def mocked_bigsuds(hostname, username, password, verify):
    if hostname == "active":
        lb = mock.Mock()
        lb.System.Failover.get_failover_state.return_value = "FAILOVER_STATE_ACTIVE"
        lb.with_session_id.return_value = lb
    elif hostname == "standby":
        lb = mock.Mock()
        lb.System.Failover.get_failover_state.return_value = "FAILOVER_STATE_STANDBY"
        lb.with_session_id.return_value = lb
    elif hostname == "broken":
        lb = mock.Mock()
        lb.System.Failover.get_failover_state.side_effect = ConnectionError()
    return lb


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config__with_first_active(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="active",
        lb2="standby",
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    lb = bigacme.lb.LoadBalancer.create_from_config(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called
    assert not lb.bigip.System.SystemInfo.get_uptime.called
    assert lb.bigip.with_session_id.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config_with_second_active(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="standby",
        lb2="active",
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    lb = bigacme.lb.LoadBalancer.create_from_config(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called
    assert not lb.bigip.System.SystemInfo.get_uptime.called
    assert lb.bigip.with_session_id.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config_first_unavailable(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="broken",
        lb2="active",
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    lb = bigacme.lb.LoadBalancer.create_from_config(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called
    assert lb.bigip.with_session_id.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config_second_unavailable(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="active",
        lb2="broken",
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    lb = bigacme.lb.LoadBalancer.create_from_config(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called
    assert lb.bigip.with_session_id.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config_with_none_active(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="standby",
        lb2="standby",
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    with pytest.raises(bigacme.lb.CouldNotConnectToBalancerError):
        bigacme.lb.LoadBalancer.create_from_config(config)


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config_with_both_broken(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="broken",
        lb2="broken",
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    with pytest.raises(bigacme.lb.CouldNotConnectToBalancerError):
        bigacme.lb.LoadBalancer.create_from_config(config)


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test_create_from_config_standalone(mock_bigsuds):
    configtp = namedtuple(
        "Config", ["lb_user", "lb_pwd", "lb1", "lb2", "lb_dg", "lb_dg_partition"]
    )
    config = configtp(
        lb_user="user",
        lb_pwd="pass",
        lb1="standby",
        lb2=None,
        lb_dg="datagroup",
        lb_dg_partition="Partition",
    )
    lb = bigacme.lb.LoadBalancer.create_from_config(config)
    assert not lb.bigip.System.Failover.get_failover_state.called
    assert lb.bigip.System.SystemInfo.get_uptime.called
    assert lb.bigip.with_session_id.called


def test_upload_certificate_access_denied():
    bigip = mock.MagicMock()
    fault = mock.MagicMock(faultstring="Access Denied:")
    bigip.Management.KeyCertificate.certificate_import_from_pem.side_effect = ServerError(
        fault, "<document></document>"
    )
    lb = bigacme.lb.LoadBalancer(bigip, "Partition", "Datagroup")
    with pytest.raises(bigacme.lb.AccessDeniedError):
        lb.upload_certificate("Patition2", "Name", "CSR")


def test_upload_certificate_weird_error():
    bigip = mock.MagicMock()
    fault = mock.MagicMock(faultstring="Computer says no!")
    bigip.Management.KeyCertificate.certificate_import_from_pem.side_effect = ServerError(
        fault, "<document></document>"
    )
    lb = bigacme.lb.LoadBalancer(bigip, "Partition", "Datagroup")
    with pytest.raises(ServerError):
        lb.upload_certificate("Patition2", "Name", "CSR")


def test_send_challenge_weird_error():
    bigip = mock.MagicMock()
    fault = mock.MagicMock(faultstring="Computer says no!")
    bigip.LocalLB.Class.add_string_class_member.side_effect = ServerError(
        fault, "<document></document>"
    )
    lb = bigacme.lb.LoadBalancer(bigip, "Partition", "Datagroup")
    with pytest.raises(ServerError):
        lb.send_challenge("domain", "path", "string")
