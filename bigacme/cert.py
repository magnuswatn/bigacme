"""Functions related to certificates"""
import os
import uuid
import json
import logging
import datetime

from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography import x509

logger = logging.getLogger(__name__)


class CertError(Exception):
    """Superclass for all cert exceptions."""

    pass


class CertificateNotFoundError(CertError):
    """Raised when the certificate was not found"""

    pass


def get_certs_that_need_action(config):
    """Returns certificate that should be installed"""
    to_be_renewed = []
    to_be_installed = []
    all_certs = get_all_certs()
    for cert in all_certs:
        if cert.about_to_expire(config.cm_renewal_days):
            to_be_renewed.append(cert)
        elif cert.status == "To be installed" and cert.old_enough(
            config.cm_delayed_days
        ):
            to_be_installed.append(cert)
    return to_be_renewed, to_be_installed


def get_all_certs():
    """Returns all the certificates that are up for renewal"""
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
    return cert.not_valid_after.isoformat(), cert.not_valid_before.isoformat()


def _check_if_cert_about_to_expire(not_after_str, threshold):
    """Check whether a certificate with the specified not after date is about to expire"""
    threshold = threshold * -1
    datelimit = datetime.datetime.today().utcnow() - datetime.timedelta(days=threshold)
    not_after = datetime.datetime.strptime(not_after_str, "%Y-%m-%dT%H:%M:%S")
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
            with path.open() as open_file:
                not_after_str, _ = _get_cert_dates(open_file.read())
        except ValueError as error:
            if str(error) == "Unable to load certificate":
                logger.warning("Could not load '%s' as a certificate", path.resolve())
                continue
            else:
                raise
        if _check_if_cert_about_to_expire(not_after_str, 0):
            logger.debug("Deleting cert '%s'", path.resolve())
            path.unlink()


class Certificate:
    """Represents a stored certificate + csr"""

    def __init__(self, partition, name):
        self.csr = self._cert = None
        self.not_after = self.not_before = None
        self.name, self.partition = name, partition
        self.status = "New"
        self.validation_method = "http-01"

    @classmethod
    def load(cls, path):
        """Load a certificate from a specified file"""
        loaded = json.loads(path.read_text())
        cert = cls(loaded["partition"], loaded["name"])
        for name, key in loaded.items():
            setattr(cert, name, key)
        return cert

    @classmethod
    def new(cls, partition, name, csr, validation_method):
        """Creates a new Certificate object from a csr"""
        cert = cls(partition, name)
        cert.csr = csr
        cert.validation_method = validation_method
        return cert

    @classmethod
    def get(cls, partition, name):
        """Get an existing certificate from disk"""
        path = Path("cert", f"{partition}_{name}.json")
        if path.exists():
            return cls.load(path)
        raise CertificateNotFoundError

    @property
    def path(self):
        return Path("cert", f"{self.partition}_{self.name}.json")

    @property
    def cert(self):
        """The pem encoded certificate"""
        return self._cert

    @cert.setter
    def cert(self, pem):
        self.not_after, self.not_before = _get_cert_dates(pem)
        self._cert = pem

    def save(self):
        """Saves the cert object to disk"""
        dumped_json = json.dumps(self.__dict__, indent=4, sort_keys=True)

        try:
            self.path.write_text(dumped_json)
        except IOError as error:
            if error.errno == 13:
                # It may be owned by another user. Try to recreate it.
                temp_path = Path(str(uuid.uuid1()))
                self.path.rename(temp_path)
                self.path.write_text(dumped_json)
                temp_path.unlink()
            else:
                raise

    def mark_as_installed(self):
        """Marks the certicate as installed, and saves it to disk"""
        self.status = "Installed"
        self.save()

    def renew(self, new_cert):
        """Backups the cert, sets a new one with status 'To be installed'"""
        backup_path = Path("cert", "backup", f"{self.partition}_{self.name}.cer")
        backup_path.write_text(self.cert)
        self.cert = new_cert
        self.status = "To be installed"
        self.save()

    def delete(self):
        """Removes the certificate from disk"""
        self.path.unlink()

    def about_to_expire(self, threshold):
        """Checks if the cert is about to expire and needs to be renewed"""
        return _check_if_cert_about_to_expire(self.not_after, threshold)

    def old_enough(self, threshold):
        """Checks if the cert is old enough to be installed"""
        datelimit = datetime.datetime.today().utcnow() - datetime.timedelta(
            days=threshold
        )
        not_before = datetime.datetime.strptime(self.not_before, "%Y-%m-%dT%H:%M:%S")
        if not_before < datelimit:
            logger.debug("'%s' is before '%s', returning True", not_before, datelimit)
            return True
        else:
            logger.debug("'%s' is after '%s', returning False", not_before, datelimit)
            return False
