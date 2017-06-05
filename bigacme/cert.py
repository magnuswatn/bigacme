"""Functions related to certificates"""
import os
import json
import logging
import datetime

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

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
    for filename in os.listdir('./cert'):
        fullpath = './cert/%s' % filename
        if os.path.isfile(fullpath):
            try:
                cert = Certificate.load(fullpath)
            except ValueError as error:
                if error.message == 'No JSON object could be decoded':
                    logger.warning('Could not load %s', fullpath)
                    continue
                else:
                    raise
            if cert.about_to_expire(config.cm_renewal_days):
                to_be_renewed.append(cert)
            elif cert.status == 'To be installed' and cert.old_enough(config.cm_delayed_days):
                to_be_installed.append(cert)
    return to_be_renewed, to_be_installed

def _get_cert_dates(pem_cert):
    """Returns the dates in the cert"""
    cert = x509.load_pem_x509_certificate(str(pem_cert), default_backend())
    logger.debug('Certificate with serial %s, has not before: %s and not after: %s (UTC)',
                 cert.serial, cert.not_valid_before, cert.not_valid_after)
    return cert.not_valid_after.isoformat(), cert.not_valid_before.isoformat()

def _check_if_cert_about_to_expire(pem_cert, threshold):
    """Check wheather a certificate from a pem file is about to expire """
    threshold = threshold * -1
    datelimit = (datetime.datetime.today().utcnow() -
                 datetime.timedelta(days=threshold))
    not_after_str, _ = _get_cert_dates(pem_cert)
    not_after = datetime.datetime.strptime(not_after_str, '%Y-%m-%dT%H:%M:%S')
    if not_after < datelimit:
        logger.debug('%s is before %s, returning True',
                     not_after, datelimit)
        return True
    else:
        logger.debug('%s is after %s, returning False',
                     not_after, datelimit)
        return False

def delete_expired_backups():
    """Deletes expired certificates from the backup folder"""
    for filename in os.listdir('./cert/backup'):
        fullpath = './cert/backup/%s' % filename
        try:
            with open(fullpath, 'r') as open_file:
                about_to_expire = _check_if_cert_about_to_expire(open_file.read(), 0)
        except ValueError as error:
            if error.message == 'Unable to load certificate':
                logger.warning('Could not load %s as a certificate', filename)
                continue
            else:
                raise
        if about_to_expire:
            logger.debug("Deleting cert %s", fullpath)
            os.remove(fullpath)

class Certificate(object):
    """Represents a stored certificate + csr"""
    def __init__(self, partition, name):
        self._csr = self._cert = self.chain = None
        self.not_after = self.not_before = self.hostnames = None
        self.name, self.partition = name, partition
        self.status = 'New'

    @classmethod
    def load(cls, fullpath):
        """Load a certificate from a specified file"""
        with open(fullpath, 'r') as json_bytes:
            loaded = json.loads(json_bytes.read())
        cert = cls(loaded['partition'], loaded['name'])
        for name, key in loaded.iteritems():
            setattr(cert, name, key)
        return cert

    @classmethod
    def new(cls, partition, name, csr):
        """Creates a new Certificate object from a csr"""
        cert = cls(partition, name)
        cert.csr = csr
        return cert

    @classmethod
    def get(cls, partition, name):
        """Get an existing certificate from disk"""
        if os.path.isfile('./cert/%s_%s.json' % (partition, name)):
            path = os.path.realpath('./cert/%s_%s.json' % (partition, name))
            return cls.load(path)
        else:
            raise CertificateNotFoundError

    @property
    def path(self):
        """The path to the json on disk"""
        return './cert/%s_%s.json' % (self.partition, self.name)

    @property
    def cert(self):
        """The pem encoded certificate"""
        return self._cert

    @cert.setter
    def cert(self, pem):
        self.not_after, self.not_before = _get_cert_dates(pem)
        self._cert = pem

    @property
    def csr(self):
        """The PEM encoded request"""
        return self._csr

    @csr.setter
    def csr(self, pem):
        csr = x509.load_pem_x509_csr(str(pem), default_backend())
        self.hostnames = []
        for extension in csr.extensions:
            if extension.oid == x509.SubjectAlternativeName.oid:
                self.hostnames = extension.value.get_values_for_type(x509.DNSName)
        # Let's Encrypt uses the commonName, in addition to the SANs, so we do the same
        if csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if common_name not in self.hostnames:
                self.hostnames.append(common_name)
        self._csr = pem

    def save(self):
        """Saves the cert object to disk"""
        with open(self.path, 'w') as open_file:
            open_file.write(
                json.dumps(self.__dict__, indent=4, sort_keys=True))

    def mark_as_installed(self):
        """Marks the certicate as installed, and saves it to disk"""
        self.status = 'Installed'
        self.save()

    def renew(self, cert, chain):
        """Backups the cert, sets a new one with status 'To be installed'"""
        backup_path = './cert/backup/%s_%s.cer' % (self.partition, self.name)
        with open(backup_path, 'w') as open_file:
            open_file.write(self.get_pem(True))
        self.cert, self.chain = cert, chain
        self.status = 'To be installed'
        self.save()

    def get_pem(self, include_chain):
        "Returns the PEM encoded cert, optionally with chain"
        chain = self.cert
        if include_chain:
            for cert in self.chain:
                chain += cert
        return chain

    def delete(self):
        """Removes the certificate from disk"""
        os.remove(self.path)

    def about_to_expire(self, threshold):
        """Checks if the cert is about to expire and needs to be renewed"""
        return _check_if_cert_about_to_expire(self.cert, threshold)

    def old_enough(self, threshold):
        """Checks if the cert is old enough to be installed"""
        datelimit = (datetime.datetime.today().utcnow() -
                     datetime.timedelta(days=threshold))
        not_before = datetime.datetime.strptime(self.not_before, '%Y-%m-%dT%H:%M:%S')
        if not_before < datelimit:
            logger.debug('%s is before %s, returning True',
                         not_before, datelimit)
            return True
        else:
            logger.debug('%s is after %s, returning False',
                         not_before, datelimit)
            return False
