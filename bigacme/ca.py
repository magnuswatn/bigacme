"""Functions that interacts with the CA"""
import logging
import datetime
from collections import namedtuple

import josepy as jose
from acme import client
from acme import messages
from acme import errors as acme_errors
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import OpenSSL

logger = logging.getLogger(__name__)


class CAError(Exception):
    """Superclass for all ca exceptions."""
    pass
class NoDesiredChallenge(CAError):
    """Raised when the CA did not provides the desired challenge for the domain"""
    pass
class GetCertificateFailedError(CAError):
    """Raised when it was not possible to get the certificate"""
    pass
class UnknownValidationType(CAError):
    """Raised when the validation type is not recognized"""
    pass

class CertificateAuthority:
    """Represent a Certificate Authority"""

    def __init__(self, configuration, test=False):
        if test:
            self.key = None
        else:
            with open(configuration.cm_key, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                    )
            self.key = jose.JWKRSA(key=private_key)
        user_agent = 'bigacme (https://github.com/magnuswatn/bigacme/)'
        network = client.ClientNetwork(self.key, user_agent=user_agent)
        directory = messages.Directory.from_json(network.get(configuration.ca).json())
        network.session.proxies = {'https': configuration.ca_proxy}
        self.client = client.ClientV2(directory, network)

    def register(self, mail):
        """Registers an account with the ca"""
        new_regr = messages.NewRegistration.from_data(email=mail, terms_of_service_agreed=True)
        self.client.new_account(new_regr)
        logger.info("Registered with the CA")

    def order_new_cert(self, csr):
        return self.client.new_order(csr)

    def get_challenges_from_order(self, order, validation_method):
        authz = order.authorizations
        desired_challenges = _return_desired_challenges(authz, validation_method)
        return self.return_tuple_from_challenges(desired_challenges)

    def answer_challenges(self, challenges):
        """Tells the CA that the challenges has been solved"""
        for challenge in challenges:
            logger.debug("Answering challenge for the domain: %s", challenge.domain)
            self.client.answer_challenge(challenge.challenge, challenge.response)

    def revoke_certifciate(self, cert_pem, reason):
        """Revokes a certificate"""
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        jose_cert = jose.util.ComparableX509(cert)
        self.client.revoke(jose_cert, reason)

    def get_certificate_from_ca(self, order):
        """Sends the CSR to the CA and gets a signed certificate in return"""
        logger.debug("Getting the certificate from the CA")
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
        try:
            order = self.client.poll_and_finalize(order, deadline=deadline)
        except acme_errors.ValidationError as error:
            error_msg = ''
            for authzr in error.failed_authzrs:
                for chall in authzr.body.challenges:
                    if chall.error != None:
                        error_msg += ('The CA could not verify the challenge for '
                                      f'{authzr.body.identifier.value}: {chall.error}.')
            raise GetCertificateFailedError(error_msg)
        except acme_errors.TimeoutError:
            raise GetCertificateFailedError(
                'Timed out while waiting for the CA to verify the challenges')
        except messages.Error as error:
            raise GetCertificateFailedError(error)
        return order.fullchain_pem

    def return_tuple_from_challenges(self, challenges):
        """Returns a challenge tuple from a list of challenges"""
        challtp = namedtuple("Authz", ["domain", "validation", "response", "challenge"])
        tuples = []
        for challenge in challenges:
            response, validation = challenge[1].response_and_validation(self.key)
            tuples += [challtp(domain=challenge[0], validation=validation, response=response,
                               challenge=challenge[1])]
        return tuples

def _return_desired_challenges(challenges, typ):
    desired_challenges = []
    for challenge in challenges:
        desired_challenge = [ch for ch in challenge.body.challenges if ch.typ == typ]
        if desired_challenge:
            desired_challenges += [[challenge.body.identifier.value, desired_challenge[0]]]
        else:
            raise NoDesiredChallenge(f'The CA didn\'t provide a {typ} challenge')
    return desired_challenges
