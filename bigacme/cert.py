"""Functions related to certificates"""
import json
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

import attr
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CertError(Exception):
    """Superclass for all cert exceptions."""


class CertificateNotFoundError(CertError):
    """Raised when the certificate was not found"""


class Status(Enum):
    NEW = "New"
    INSTALLED = "Installed"
    TO_BE_INSTALLED = "To be installed"


class ValidationMethod(Enum):
    HTTP01 = "http-01"
    DNS01 = "dns-01"


def get_certs_that_need_action(config):
    """Returns certificate that should be installed"""
    to_be_renewed = []
    to_be_installed = []
    all_certs = get_all_certs()
    for cert in all_certs:
        if cert.up_for_renewal(config.cm_renewal_days):
            to_be_renewed.append(cert)
        elif cert.up_for_installation(config.cm_delayed_days):
            to_be_installed.append(cert)
    return to_be_renewed, to_be_installed


def get_all_certs():
    """Returns all the stored certificates"""
    certs = []
    for path in Path("cert").iterdir():
        if path.is_file():
            try:
                cert = Certificate.load(path)
            except ValueError as error:
                logger.warning("Could not load '%s': %s", path.resolve(), error)
                continue
            certs.append(cert)
    return certs


def _get_cert_dates(pem_cert):
    """Returns the dates in the cert"""
    cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
    logger.debug(
        "Certificate with serial '%s', has not before: '%s' and not after: '%s' (UTC)",
        cert.serial_number,
        cert.not_valid_before,
        cert.not_valid_after,
    )
    return cert.not_valid_after, cert.not_valid_before


def _check_if_cert_about_to_expire(not_after, threshold):
    """
    Check whether a certificate with the specified
    not after date is about to expire.
    """
    datelimit = datetime.today().utcnow() - timedelta(days=threshold * -1)

    if not_after < datelimit:
        logger.debug("'%s' is before '%s', returning True", not_after, datelimit)
        return True
    else:
        logger.debug("'%s' is after '%s', returning False", not_after, datelimit)
        return False


def delete_expired_backups():
    """Deletes expired certificates from the backup folder"""
    for path in Path("cert", "backup").iterdir():
        try:
            not_after, _ = _get_cert_dates(path.read_text())
        except ValueError as error:
            logger.warning(
                "Could not load '%s' as a certificate: %s", path.resolve(), error
            )
            continue
        if _check_if_cert_about_to_expire(not_after, 0):
            logger.debug("Deleting cert '%s'", path.resolve())
            path.unlink()


@attr.s
class Certificate:
    """Represents a stored certificate + csr"""

    name = attr.ib()
    partition = attr.ib()
    path = attr.ib()
    csr = attr.ib()
    _cert = attr.ib()
    status = attr.ib()
    validation_method = attr.ib()
    not_after = attr.ib()
    not_before = attr.ib()

    @classmethod
    def create(cls, partition, name, **kwargs):
        path = Path("cert", f"{partition}_{name}.json")

        csr = kwargs.pop("csr", None)
        cert = kwargs.pop("cert", None)
        status = kwargs.pop("status", Status.NEW)
        validation_method = kwargs.pop("validation_method", ValidationMethod.HTTP01)

        not_after = kwargs.pop("not_after", datetime.fromtimestamp(0))
        not_before = kwargs.pop("not_before", datetime.fromtimestamp(0))

        return cls(
            name,
            partition,
            path,
            csr,
            cert,
            status,
            validation_method,
            not_after,
            not_before,
        )

    @classmethod
    def load(cls, path):
        """Load a certificate from a specified file"""

        loaded = json.loads(path.read_text())

        not_after = datetime.strptime(loaded.pop("not_after"), "%Y-%m-%dT%H:%M:%S")
        not_before = datetime.strptime(loaded.pop("not_before"), "%Y-%m-%dT%H:%M:%S")

        status = Status(loaded.pop("status"))
        validation_method = ValidationMethod(
            # default to http-01 if not specified
            # (for backwards compability)
            loaded.pop("validation_method", "http-01")
        )

        loaded.update(
            {
                "not_before": not_before,
                "not_after": not_after,
                "status": status,
                "validation_method": validation_method,
            }
        )

        return cls.create(**loaded)

    @classmethod
    def new(cls, partition, name, csr, validation_method):
        """Creates a new Certificate object from a csr"""
        return cls.create(partition, name, csr=csr, validation_method=validation_method)

    @classmethod
    def get(cls, partition, name):
        """Get an existing certificate from disk"""
        path = Path("cert", f"{partition}_{name}.json")
        if path.exists():
            return cls.load(path)
        raise CertificateNotFoundError()

    @property
    def cert(self):
        """The pem encoded certificate (with chain)"""
        return self._cert

    @cert.setter
    def cert(self, pem):
        self.not_after, self.not_before = _get_cert_dates(pem)
        self._cert = pem

    def save(self):
        """Saves the cert object to disk"""

        dumped_json = json.dumps(
            {
                "name": self.name,
                "partition": self.partition,
                "status": self.status.value,
                "not_before": self.not_before.isoformat(),
                "not_after": self.not_after.isoformat(),
                "csr": self.csr,
                "cert": self.cert,
                "validation_method": self.validation_method.value,
            },
            indent=4,
            sort_keys=True,
        )

        try:
            self.path.write_text(dumped_json)
        except IOError as error:
            if error.errno == 13:
                # It may be owned by another user,
                # try to recreate it.
                temp_path = Path(str(uuid.uuid1()))
                self.path.rename(temp_path)
                self.path.write_text(dumped_json)
                temp_path.unlink()
            else:
                raise

    def mark_as_installed(self):
        """Marks the certicate as installed, and saves it to disk"""
        self.status = Status.INSTALLED
        self.save()

    def renew(self, new_cert):
        """Backups the cert, sets a new one with status 'To be installed'"""
        backup_path = Path("cert", "backup", f"{self.partition}_{self.name}.cer")
        backup_path.write_text(self.cert)
        self.cert = new_cert
        self.status = Status.TO_BE_INSTALLED
        self.save()

    def delete(self):
        """Removes the certificate from disk"""
        self.path.unlink()

    def up_for_renewal(self, threshold):
        """Checks if the cert is in need of renewal"""
        return _check_if_cert_about_to_expire(self.not_after, threshold)

    def up_for_installation(self, threshold):
        """Checks if the cert is ready to be installed"""

        if self.status != Status.TO_BE_INSTALLED:
            return False

        datelimit = datetime.today().utcnow() - timedelta(days=threshold)

        if self.not_before < datelimit:
            logger.debug(
                "'%s' is before '%s', returning True", self.not_before, datelimit
            )
            return True
        else:
            logger.debug(
                "'%s' is after '%s', returning False", self.not_before, datelimit
            )
            return False
