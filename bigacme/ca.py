"""Functions that interacts with the CA"""
import datetime
import json
import logging
import re
from pathlib import Path

import attr
import josepy as jose
import OpenSSL
from acme import client
from acme import errors as acme_errors
from acme import messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


USER_AGENT = "bigacme (https://github.com/magnuswatn/bigacme/)"
CERT_TIMEOUT = 90


class CAError(Exception):
    """Superclass for all ca exceptions."""


class CouldNotRetrieveDirectoryFromCA(CAError):
    """Could not retrieve the direcotry from the CA"""


class NoDesiredChallenge(CAError):
    """Raised when the CA did not provides the desired challenge for the domain"""


class GetCertificateFailedError(CAError):
    """Raised when it was not possible to get the certificate"""


class UnknownValidationType(CAError):
    """Raised when the validation type is not recognized"""


class AccountInfoExistsError(CAError):
    """Raised when the account file already exists."""


class ReceivedInvalidCertificateError(CAError):
    """Raised when the certificate returned from the CA as malformed."""


@attr.s
class ChallengeToBeSolved:
    """
    A challenge that needs to be solved to retrive
    a cert for the specified domain.
    """

    identifier = attr.ib()
    challenge = attr.ib()
    validation = attr.ib()
    response = attr.ib()

    @classmethod
    def create(cls, identifier, challenge, key):
        response, validation = challenge.response_and_validation(key)
        return cls(identifier, challenge, validation, response)


@attr.s
class CertificateAuthority:
    """Represent a Certificate Authority"""

    kid = attr.ib()
    key = attr.ib()
    client = attr.ib()
    account_file = attr.ib()

    @classmethod
    def create_from_config(cls, configuration):
        account_file = Path(configuration.cm_account)

        try:
            account_info = json.loads(account_file.read_text())
        except FileNotFoundError:
            # For registration and testing.
            kid, key = None, None
        else:
            kid = account_info["kid"]
            key = jose.JWKRSA.from_json(account_info["key"])

        network = client.ClientNetwork(
            key, user_agent=USER_AGENT, account=messages.RegistrationResource(uri=kid)
        )

        network.session.proxies = {"https": configuration.ca_proxy}

        try:
            directory = messages.Directory.from_json(
                network.get(configuration.ca).json()
            )
        except ValueError as error:
            raise CouldNotRetrieveDirectoryFromCA(error) from error

        acme_client = client.ClientV2(directory, network)
        return cls(kid, key, acme_client, account_file)

    def _create_account_key(self) -> None:
        """Creates an account key"""
        logger.debug("Generating account key")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        self.key = jose.JWKRSA(key=private_key)
        self.client.net.key = self.key

    def _save_account(self) -> None:
        """Saves the account key and id to the file specified in the config"""
        if self.account_file.exists():
            raise AccountInfoExistsError()

        account_info = {"kid": self.kid, "key": self.key.to_json()}
        account_json = json.dumps(account_info, indent=4, sort_keys=True)

        # Saving private key to file - we must be careful with the permissions
        self.account_file.touch(mode=0o640)
        self.account_file.write_text(account_json)
        self.account_file.chmod(0o440)

    def register(self, mail: str) -> None:
        """Registers an account with the ca"""
        self._create_account_key()
        # The user has already agreed to the tos in main.py
        new_regr = messages.NewRegistration.from_data(
            email=mail, terms_of_service_agreed=True
        )
        regr = self.client.new_account(new_regr)
        self.kid = regr.uri
        self._save_account()
        logger.info("Registered with the CA. Key ID: '%s'", self.kid)

    def order_new_cert(self, csr: str) -> messages.OrderResource:
        """Orders a new certificate"""
        return self.client.new_order(csr)

    def get_challenges_to_solve_from_order(self, order, validation_method):
        """
        Returns the challenges that needs to be solved from the order,
        filtered by the specified validation method.
        """
        challenges_to_be_solved = []
        for authz in order.authorizations:
            if authz.body.status == messages.STATUS_VALID:
                logger.debug(
                    "Authorization '%s' for domain '%s' "
                    "is already valid, so no need "
                    "to solve a challenge for this authorization.",
                    authz.uri,
                    authz.body.identifier.value,
                )
                continue
            elif authz.body.status != messages.STATUS_PENDING:
                raise CAError(
                    f"Unexpected status for authorization: {authz.body.status.name}"
                )

            for challenge in authz.body.challenges:
                if challenge.typ == validation_method.value:
                    if challenge.status != messages.STATUS_PENDING:
                        raise CAError(
                            f"Unexpected status for challenge: {challenge.status}"
                        )
                    challenges_to_be_solved.append(
                        ChallengeToBeSolved.create(
                            authz.body.identifier.value, challenge, self.key
                        )
                    )
                    break
            else:
                raise NoDesiredChallenge(
                    f"The CA didn't provide a '{validation_method.value}' challenge "
                    f"for domain '{authz.body.identifier.value}'. It provided: "
                    f"{', '.join([chall.typ for chall in authz.body.challenges])}."
                )
        return challenges_to_be_solved

    def answer_challenges(self, challenges) -> None:
        """Tells the CA that the challenges has been solved"""
        for challenge in challenges:
            logger.debug("Answering challenge for '%s'", challenge.identifier)
            self.client.answer_challenge(challenge.challenge, challenge.response)

    def revoke_certifciate(self, cert_pem: str, reason: int) -> None:
        """Revokes a certificate"""
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        jose_cert = jose.util.ComparableX509(cert)
        self.client.revoke(jose_cert, reason)

    def get_certificate_from_ca(self, order: messages.OrderResource) -> str:
        """Sends the CSR to the CA and gets a signed certificate in return"""
        logger.debug("Getting the certificate from the CA")
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=CERT_TIMEOUT)
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
            raise GetCertificateFailedError(error_msg) from error
        except acme_errors.TimeoutError as error:
            raise GetCertificateFailedError(
                "Timed out while waiting for the CA to verify the challenges"
            ) from error
        except acme_errors.Error as error:
            raise GetCertificateFailedError(error) from error

        # sanity check, ref 11.3 of the ACME spec
        _validate_cert_chain(order.fullchain_pem)

        return order.fullchain_pem


def _validate_cert_chain(pem_cert: str) -> None:
    """Validates that the PEM chain only includes certificates"""
    for begin_string in re.findall(r"-----BEGIN [^-]*-----", pem_cert):
        if begin_string != "-----BEGIN CERTIFICATE-----":
            raise ReceivedInvalidCertificateError(
                f"Received certificate with invalid BEGIN string: {begin_string}"
            )
