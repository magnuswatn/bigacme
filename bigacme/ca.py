"""Functions that interacts with the CA"""
import os
import re
import json
import logging
import datetime
from collections import namedtuple

import josepy as jose
from acme import client
from acme import messages
from acme import errors as acme_errors
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

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


class AccountInfoExistsError(CAError):
    """Raised when the account file already exists."""

    pass


class ReceivedInvalidCertificateError(CAError):
    """Raised when the certificate returned from the CA as malformed."""

    pass


class CertificateAuthority:
    """Represent a Certificate Authority"""

    def __init__(self, configuration):
        self.account_file = configuration.cm_account
        user_agent = "bigacme (https://github.com/magnuswatn/bigacme/)"

        try:
            self.load_account()
        except FileNotFoundError:
            # For registration and testing
            self.kid, self.key = None, None

        network = client.ClientNetwork(
            self.key,
            user_agent=user_agent,
            account=messages.RegistrationResource(uri=self.kid),
        )

        network.session.proxies = {"https": configuration.ca_proxy}
        directory = messages.Directory.from_json(network.get(configuration.ca).json())
        self.client = client.ClientV2(directory, network)

    def load_account(self):
        """Loads the account information (key and kid) from disk"""
        with open(self.account_file, "r") as open_file:
            account_json = open_file.read()
        account_info = json.loads(account_json)
        self.kid = account_info["kid"]
        self.key = jose.JWKRSA.from_json(account_info["key"])

    def create_account_key(self):
        """Creates an account key"""
        logger.debug("Generating account key")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        self.key = jose.JWKRSA(key=private_key)
        self.client.net.key = self.key

    def save_account(self):
        """Saves the account key and id to the file specified in the config"""
        if os.path.exists(self.account_file):
            raise AccountInfoExistsError

        account_info = {"kid": self.kid, "key": self.key.to_json()}
        account_json = json.dumps(account_info, indent=4, sort_keys=True)

        # Saving private key to file - we must be careful with the permissions
        file_name = self.account_file
        with os.fdopen(
            os.open(file_name, os.O_WRONLY | os.O_CREAT, 0o440), "w"
        ) as open_file:
            open_file.write(account_json)

    def register(self, mail):
        """Registers an account with the ca"""
        self.create_account_key()
        # The user has already agreed to the tos in main.py
        new_regr = messages.NewRegistration.from_data(
            email=mail, terms_of_service_agreed=True
        )
        regr = self.client.new_account(new_regr)
        self.kid = regr.uri
        self.save_account()
        logger.info("Registered with the CA. Key ID: %s", self.kid)

    def order_new_cert(self, csr):
        """Orders a new certificate"""
        return self.client.new_order(csr)

    def get_challenges_from_order(self, order, validation_method):
        """Returns the challenges for the specified validation method from the order"""
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
            error_msg = ""
            for authzr in error.failed_authzrs:
                for chall in authzr.body.challenges:
                    if chall.error != None:
                        error_msg += (
                            "The CA could not verify the challenge for "
                            f"{authzr.body.identifier.value}: {chall.error}."
                        )
            raise GetCertificateFailedError(error_msg)
        except acme_errors.TimeoutError:
            raise GetCertificateFailedError(
                "Timed out while waiting for the CA to verify the challenges"
            )
        except messages.Error as error:
            raise GetCertificateFailedError(error)

        # sanity check, ref 11.3 of the ACME spec
        _validate_cert_chain(order.fullchain_pem)

        return order.fullchain_pem

    def return_tuple_from_challenges(self, challenges):
        """Returns tuples with the needed info from the challenges (incl. signed validation)"""
        challtp = namedtuple("Authz", ["domain", "validation", "response", "challenge"])
        tuples = []
        for challenge in challenges:
            # challenge is a tuple with the domain name and the challenge
            response, validation = challenge[1].response_and_validation(self.key)
            tuples += [
                challtp(
                    domain=challenge[0],
                    validation=validation,
                    response=response,
                    challenge=challenge[1],
                )
            ]
        return tuples


def _return_desired_challenges(challenges, typ):
    desired_challenges = []
    for challenge in challenges:
        desired_challenge = [ch for ch in challenge.body.challenges if ch.typ == typ]
        if desired_challenge:
            desired_challenges += [
                (challenge.body.identifier.value, desired_challenge[0])
            ]
        else:
            raise NoDesiredChallenge(f"The CA didn't provide a '{typ}' challenge")
    return desired_challenges


def _validate_cert_chain(pem_cert):
    """Validates that the PEM chain only includes certificates"""
    for begin_string in re.findall(r"-----BEGIN [^-]*-----", pem_cert):
        if begin_string != "-----BEGIN CERTIFICATE-----":
            raise ReceivedInvalidCertificateError(
                f"Received certificate with invalid BEGIN string: {begin_string}"
            )
