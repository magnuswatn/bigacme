"""Tests for ca.py"""
from unittest import mock
from unittest.mock import MagicMock

import pytest
from acme import challenges
from acme import errors as acme_errors
from acme import messages

from bigacme import ca
from bigacme.ca import CAError, NoDesiredChallenge
from bigacme.cert import ValidationMethod


@pytest.fixture()
def mocked_ca():
    acme_ca = ca.CertificateAuthority(None, None, None, None)
    acme_ca.client = MagicMock()
    acme_ca._create_account_key()
    return acme_ca


class DummyChallengeToBeSolved:
    @classmethod
    def create(cls, identifier, challenge, key):
        return challenge


class TestGetChallengesFromOrder:
    def test_normal_case(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz1_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz1_chall3 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz1_chall1, authz1_chall2, authz1_chall3],
            }
        )

        authz2_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz2_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz2_chall3 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz2 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz2_chall1, authz2_chall2, authz2_chall3],
            }
        )

        order = MagicMock(authorizations=[pending_autz1, pending_autz2])

        with mock.patch("bigacme.ca.ChallengeToBeSolved", new=DummyChallengeToBeSolved):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.HTTP01
            )

        assert authz1_chall1 and authz2_chall1 in challenges_to_be_solved

    def test_normal_case_with_dns(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz1_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz1_chall3 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz1_chall1, authz1_chall2, authz1_chall3],
            }
        )

        authz2_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz2_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz2_chall3 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz2 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz2_chall1, authz2_chall2, authz2_chall3],
            }
        )

        order = MagicMock(authorizations=[pending_autz1, pending_autz2])

        with mock.patch("bigacme.ca.ChallengeToBeSolved", new=DummyChallengeToBeSolved):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.DNS01
            )

        assert authz1_chall2 and authz2_chall2 in challenges_to_be_solved

    def test_no_desired_challenge(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz1_chall2 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz1_chall1, authz1_chall2],
            }
        )

        authz2_chall1 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz2_chall2 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz2 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz2_chall1, authz2_chall2],
            }
        )

        order = MagicMock(authorizations=[pending_autz1, pending_autz2])

        with pytest.raises(NoDesiredChallenge):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.HTTP01
            )

    def test_all_challenges_already_valid(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_VALID)

        pending_autz1 = MagicMock(
            **{"body.status": messages.STATUS_VALID, "body.challenges": [authz1_chall1]}
        )

        authz2_chall1 = MagicMock(typ="dns-01", status=messages.STATUS_VALID)

        pending_autz2 = MagicMock(
            **{"body.status": messages.STATUS_VALID, "body.challenges": [authz2_chall1]}
        )

        order = MagicMock(authorizations=[pending_autz1, pending_autz2])

        challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
            order, ValidationMethod.DNS01
        )

        assert challenges_to_be_solved == []

    def test_some_valid_some_pending(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz1_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz1_chall3 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz1_chall1, authz1_chall2, authz1_chall3],
            }
        )

        authz2_chall1 = MagicMock(typ="dns-01", status=messages.STATUS_VALID)

        pending_autz2 = MagicMock(
            **{"body.status": messages.STATUS_VALID, "body.challenges": [authz2_chall1]}
        )

        order = MagicMock(authorizations=[pending_autz1, pending_autz2])

        with mock.patch("bigacme.ca.ChallengeToBeSolved", new=DummyChallengeToBeSolved):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.HTTP01
            )

        assert challenges_to_be_solved == [authz1_chall1]

    def test_invalid_authz(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_INVALID)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_INVALID,
                "body.challenges": [authz1_chall1],
            }
        )

        order = MagicMock(authorizations=[pending_autz1])

        with pytest.raises(CAError):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.HTTP01
            )

    def test_unexpected_status_for_desired_challenge(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz1_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_INVALID)
        authz1_chall3 = MagicMock(typ="what-01", status=messages.STATUS_PENDING)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz1_chall1, authz1_chall2, authz1_chall3],
            }
        )

        order = MagicMock(authorizations=[pending_autz1])

        with pytest.raises(CAError):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.DNS01
            )

    def test_unexpected_status_for_other_challenge(self, mocked_ca):

        authz1_chall1 = MagicMock(typ="http-01", status=messages.STATUS_PENDING)
        authz1_chall2 = MagicMock(typ="dns-01", status=messages.STATUS_PENDING)
        authz1_chall3 = MagicMock(typ="what-01", status=messages.STATUS_INVALID)

        pending_autz1 = MagicMock(
            **{
                "body.status": messages.STATUS_PENDING,
                "body.challenges": [authz1_chall1, authz1_chall2, authz1_chall3],
            }
        )

        order = MagicMock(authorizations=[pending_autz1])

        with mock.patch("bigacme.ca.ChallengeToBeSolved", new=DummyChallengeToBeSolved):
            challenges_to_be_solved = mocked_ca.get_challenges_to_solve_from_order(
                order, ValidationMethod.HTTP01
            )

        assert challenges_to_be_solved == [authz1_chall1]


def test_ChallengeToBeSolved():
    challenge = MagicMock()
    challenge.response_and_validation.side_effect = [("response", "validation")]
    ctbs = ca.ChallengeToBeSolved.create("identifier", challenge, "key")

    assert ctbs.challenge == challenge
    assert ctbs.identifier == "identifier"
    assert ctbs.response == "response"
    assert ctbs.validation == "validation"

    challenge.response_and_validation.assert_called_once_with("key")


def test_validate_cert_chain_vaild_chain():
    """With a normal chain with certs, nothing should happen"""
    pem_chain = """
    -----BEGIN CERTIFICATE-----
    tralallalalal
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    tralallalalal
    -----END CERTIFICATE-----"""
    ca._validate_cert_chain(pem_chain)


def test_validate_cert_chain_invaild_chain():
    """Should raise an exception if the cert chain contains fishy stuff"""
    pem_chain = """
    -----BEGIN CERTIFICATE-----
    tralallalalal
    -----END CERTIFICATE-----
    -----BEGIN PRIVATE KEY-----
    tralallalalal
    -----END PRIVATE KEY-----"""
    with pytest.raises(ca.ReceivedInvalidCertificateError):
        ca._validate_cert_chain(pem_chain)


def test_get_certificate_from_ca_timeout():
    fake_ca = MagicMock(spec=ca.CertificateAuthority)
    order = MagicMock()
    fake_ca.client = MagicMock()
    fake_ca.client.poll_and_finalize.side_effect = acme_errors.TimeoutError
    with pytest.raises(ca.GetCertificateFailedError) as error:
        ca.CertificateAuthority.get_certificate_from_ca(fake_ca, order)
    assert (
        str(error.value)
        == "Timed out while waiting for the CA to verify the challenges"
    )


def test_get_certificate_from_ca_error_from_server():
    fake_ca = MagicMock(spec=ca.CertificateAuthority)
    order = MagicMock()
    fake_ca.client = MagicMock()
    fake_ca.client.poll_and_finalize.side_effect = messages.Error
    with pytest.raises(ca.GetCertificateFailedError) as error:
        ca.CertificateAuthority.get_certificate_from_ca(fake_ca, order)


def test_get_certificate_from_ca_weird_error():
    fake_ca = MagicMock(spec=ca.CertificateAuthority)
    order = MagicMock()
    fake_ca.client = MagicMock()
    fake_ca.client.poll_and_finalize.side_effect = acme_errors.UnexpectedUpdate("what")
    with pytest.raises(ca.GetCertificateFailedError) as error:
        ca.CertificateAuthority.get_certificate_from_ca(fake_ca, order)
    assert str(error.value) == "what"
