import mock
from collections import namedtuple
from bigsuds import ConnectionError

import pytest
import bigacme.lb


def mocked_bigsuds(hostname, username, password, verify):
    if hostname == "active":
        lb = mock.Mock()
        lb.System.Failover.get_failover_state.return_value = "FAILOVER_STATE_ACTIVE"
    elif hostname == "standby":
        lb = mock.Mock()
        lb.System.Failover.get_failover_state.return_value = "FAILOVER_STATE_STANDBY"
    elif hostname == "broken":
        lb = mock.Mock()
        lb.System.Failover.get_failover_state.side_effect = ConnectionError()
    return lb


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test__init__with_first_active(mock_bigsuds):
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
    lb = bigacme.lb.LoadBalancer(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called
    assert not lb.bigip.System.SystemInfo.get_uptime.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test__init__with_second_active(mock_bigsuds):
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
    lb = bigacme.lb.LoadBalancer(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called
    assert not lb.bigip.System.SystemInfo.get_uptime.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test__init__first_unavailable(mock_bigsuds):
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
    lb = bigacme.lb.LoadBalancer(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test__init__second_unavailable(mock_bigsuds):
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
    lb = bigacme.lb.LoadBalancer(config)
    assert (
        lb.bigip.System.Failover.get_failover_state.return_value
        == "FAILOVER_STATE_ACTIVE"
    )
    assert lb.bigip.System.Failover.get_failover_state.called


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test__init__with_none_active(mock_bigsuds):
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
    with pytest.raises(bigacme.lb.NoActiveLoadBalancersError):
        bigacme.lb.LoadBalancer(config)


@mock.patch("bigacme.lb.bigsuds.BIGIP", side_effect=mocked_bigsuds)
def test__init__standalone(mock_bigsuds):
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
    lb = bigacme.lb.LoadBalancer(config)
    assert not lb.bigip.System.Failover.get_failover_state.called
    assert lb.bigip.System.SystemInfo.get_uptime.called
