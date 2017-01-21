"""Functions that interacts with the CA"""
import os
import logging
from collections import namedtuple

from acme import client
from acme import messages
from acme import jose
from acme import errors as acme_errors
import OpenSSL

logger = logging.getLogger(__name__)


class CAError(Exception):
    """Superclass for all ca exceptions."""
    pass
class NoHTTPChallenge(CAError):
    """Raised when there is no http challenge to be solved"""
    pass
class GetCertificateFailedError(CAError):
    """Raised when it was not possible to get the certificate"""
    pass

def _set_proxy(configuration):
    """Sets the proxy server to the specified server (if any)"""
    if configuration.ca_proxy:
        os.environ["https_proxy"] = configuration.ca_proxy

def _unset_proxy(configuration):
    """Removes the set proxy"""
    if configuration.ca_proxy:
        os.environ["https_proxy"] = ""

def get_client(configuration, key):
    """Returns an acme client initialized with the specified key"""
    _set_proxy(configuration)
    network = client.ClientNetwork(key, user_agent="Big-ACME")
    acme_client = client.Client(directory=configuration.ca, key=key, net=network)
    _unset_proxy(configuration)
    return acme_client

def register_with_ca(configuration, acme_client, mail):
    """Registers an account with the specified ca"""
    _set_proxy(configuration)
    registration = messages.NewRegistration.from_data(email=mail)
    regr = acme_client.register(registration)
    logger.info("Auto-accepting TOS: %s", regr.terms_of_service)
    acme_client.agree_to_tos(regr)
    logger.info("Registered with the CA")
    _unset_proxy(configuration)

def get_http_challenge_for_domains(configuration, acme_client, hostnames, key):
    """Gets challenges from the CA, and return the HTTP ones"""
    challenges = _get_challenge_for_domains(configuration, acme_client, hostnames)
    http_challenges = _return_http_challenges(challenges)
    return _return_tuple_from_challenges(http_challenges, key), challenges

def _get_challenge_for_domains(configuration, acme_client, hostnames):
    """Asks the CA for challenges for the specified domains"""
    _set_proxy(configuration)
    challenges = []
    for hostname in hostnames:
        challenges += [acme_client.request_domain_challenges(hostname)]
    _unset_proxy(configuration)
    return challenges

def _return_http_challenges(challenges):
    """Returns the http challenge"""
    http_challenges = []
    for challenge in challenges:
        http_challenge = False
        logger.debug("This challenge is for the domain: %s", challenge.body.identifier.value)
        for subchallenge in challenge.body.challenges:
            logger.debug("This challenge is of type %s", subchallenge.chall.typ)
            if subchallenge.chall.typ == "http-01":
                logger.debug("This challenge is of http :-)")
                http_challenges += [[challenge.body.identifier.value, subchallenge]]
                http_challenge = True
        if not http_challenge:
            logger.debug("Found no http challenge for this domain, raising NoHTTPChallenge")
            raise NoHTTPChallenge
    return http_challenges

def _return_tuple_from_challenges(http_challenges, key):
    """Returns a challenge tuple from a list of challenges"""
    challtp = namedtuple("Authz", ["domain", "path", "validation", "response", "challenge"])
    tuples = []
    for challenge in http_challenges:
        response, validation = challenge[1].response_and_validation(key)
        tuples += [challtp(domain=challenge[0], path=challenge[1].path,
                           validation=validation, response=response, challenge=challenge[1])]
    return tuples

def answer_challenges(configuration, acme_client, challenges):
    """Tells the CA that the challenges has been solved"""
    _set_proxy(configuration)
    for challenge in challenges:
        logger.debug("Answering challenge for the domain: %s", challenge.domain)
        acme_client.answer_challenge(challenge.challenge, challenge.response)
    _unset_proxy(configuration)

def get_certificate_from_ca(configuration, acme_client, csr_pem, authorizations):
    """Sends the CSR to the CA and gets a signed certificate in return"""
    _set_proxy(configuration)
    csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)
    jose_csr = jose.util.ComparableX509(csr)
    logger.debug("Getting the certificate from the CA")
    try:
        certificateresource, _ = acme_client.poll_and_request_issuance(jose_csr, authorizations)
    except acme_errors.PollError as error:
        if error.timeout:
            raise GetCertificateFailedError(
                "Timed out while waiting for the CA to verify the challenges")
        else:
            raise GetCertificateFailedError("The CA could not verify the challenges")

    cert = certificateresource.body._dump(OpenSSL.crypto.FILETYPE_PEM) # pylint: disable=protected-access
    chain_certs = acme_client.fetch_chain(certificateresource)
    chain = []
    for chaincert in chain_certs:
        chain.append(chaincert._dump(OpenSSL.crypto.FILETYPE_PEM)) # pylint: disable=protected-access
    _unset_proxy(configuration)
    return cert, chain

def revoke_certifciate(configuration, acme_client, cert_pem):
    """Revokes a certificate"""
    _set_proxy(configuration)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    jose_cert = jose.util.ComparableX509(cert)
    acme_client.revoke(jose_cert)
    _unset_proxy(configuration)
