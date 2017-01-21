"""Functions related to certificates"""
import os
import datetime
import logging

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

def get_hostnames_from_csr(csr_pem):
    """Returns the hostnames from a PEM encoded CSR"""
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    names = []
    for extension in csr.extensions:
        if extension.oid == x509.SubjectAlternativeName.oid:
            names = extension.value.get_values_for_type(x509.DNSName) # kva med ip-adressar?
    if not names:
        # No SAN extension, we use the commonName instead
        names = [csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value]
    return names

def check_for_renewals(configuration):
    """Goes through the cert folder and check if any cert should be renewed"""
    renewals = []
    for filename in os.listdir('./cert'):
        fullpath = './cert/%s' % filename
        if os.path.isfile(fullpath):
            if _check_if_cert_about_to_expire(fullpath, configuration.cm_renewal_days):
                renewals.append(filename)
    return renewals

def load_associated_csr(certname):
    """Loads the csr associated with the specified cert file"""
    csrname = '%scsr' % certname[:-3]
    with open('./csr/%s' % csrname, 'r') as openfile:
        csr = openfile.read()
    return csr

def _check_if_cert_about_to_expire(cert_file, threshold):
    """Check wheather a certificate from a pem file is about to expire """
    threshold = threshold * -1
    datelimit = (datetime.datetime.today().utcnow() -
                 datetime.timedelta(days=threshold))
    with open(cert_file, 'r') as cert_bytes:
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes.read(),
                                                  default_backend())
        except ValueError as error:
            if error.message == 'Unable to load certificate':
                logger.warning('Could not load %s as a certificate', cert_file)
                return None
            else:
                raise
        else:
            logger.debug('Certificate %s, with serial %s, expires %s',
                         cert_file, cert.serial, cert.not_valid_after)
        if cert.not_valid_after < datelimit:
            logger.debug('%s is before %s, returning True',
                         cert.not_valid_after, datelimit)
            return True
        else:
            logger.debug('%s is after %s, returning False',
                         cert.not_valid_after, datelimit)
            return False

def _check_if_cert_is_old_enough(cert_file, threshold):
    """Checks wheather a certificate is old enough to be installed"""
    datelimit = (datetime.datetime.today().utcnow() -
                 datetime.timedelta(days=threshold))
    with open(cert_file, 'r') as cert_bytes:
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes.read(),
                                                  default_backend())
        except ValueError as error:
            if error.message == 'Unable to load certificate':
                logger.warning('Could not load %s as a certificate', cert_file)
                return None
            else:
                raise
        else:
            logger.debug('Certificate %s, with serial %s, expires %s',
                         cert_file, cert.serial, cert.not_valid_after)
        if cert.not_valid_before < datelimit:
            logger.debug('%s is before %s, returning True',
                         cert.not_valid_before, datelimit)
            return True
        else:
            logger.debug('%s is after %s, returning False',
                         cert.not_valid_before, datelimit)
            return False

def save_cert_to_disk(partition, alias, pem):
    """Saves a cert to disk"""
    filename = './cert/%s_%s.cer' % (partition, alias)
    with open(filename, 'w') as openfile:
        openfile.write(pem)

def save_renewed_cert_to_disk(partition, alias, pem):
    """Saves a cert to disk the to_be_installed folder"""
    filename = './cert/to_be_installed/%s_%s.cer' % (partition, alias)
    with open(filename, 'w') as openfile:
        openfile.write(pem)

def save_csr_to_disk(partition, alias, pem):
    """Saves a csr to disk"""
    filename = './csr/%s_%s.csr' % (partition, alias)
    with open(filename, 'w') as openfile:
        openfile.write(pem)

def load_renewed_cert_from_disk(partition, alias):
    """Loads a renewed cert from disk"""
    filename = './cert/to_be_installed/%s_%s.cer' % (partition, alias)
    with open(filename, 'r') as openfile:
        cert_pem = openfile.read()
    return cert_pem

def load_csr_from_disk(partition, alias):
    """Loads a csr from disk"""
    filename = './csr/%s_%s.csr' % (partition, alias)
    with open(filename, 'r') as openfile:
        csr_pem = openfile.read()
    return csr_pem

def move_renewed_cert(certfile):
    """Moves a renewed cert to the cert folder"""
    old_path = './cert/to_be_installed/%s' % certfile
    new_path = './cert/%s' % certfile
    os.rename(old_path, new_path)

def delete_expired_backups():
    """Deletes expired certificates from the backup folder"""
    for filename in os.listdir('./cert/backup'):
        fullpath = './cert/backup/%s' % filename
        if _check_if_cert_about_to_expire(fullpath, 0):
            logger.debug("Deleting cert %s", fullpath)
            os.remove(fullpath)

def move_cert_to_backup(certfile):
    """Backs up the specified certiticate"""
    old_path = './cert/%s' % certfile
    new_path = './cert/backup/%s' % certfile
    os.rename(old_path, new_path)

def get_certificate_to_be_installed(configuration):
    """Returns certificate that should be installed"""
    to_be_installed = []
    for filename in os.listdir('./cert/to_be_installed'):
        fullpath = './cert/to_be_installed/%s' % filename
        if _check_if_cert_is_old_enough(fullpath, configuration.cm_delayed_days):
            to_be_installed.append(filename)
    return to_be_installed

def get_name_from_filename(filename):
    """Gets the partition and name from a filename"""
    partition = filename.split('_', 1)[0]
    name = filename.split('_', 1)[1][:-4]
    return partition, name

def remve_cert(partition, name):
    """Removes a certificate so that it won't get renewed"""
    cert_name = './cert/%s_%s.cer' % (partition, name)
    uninstalled_cert_name = './cert/to_be_installed/%s_%s.cer' % (partition, name)
    csr_name = './csr/%s_%s.csr' % (partition, name)
    failures = 0
    try:
        os.remove(csr_name)
    except OSError as error:
        if error.errno == 2:
            logger.error('Could not delete certificate %s from partition %s as it was not found',
                         name, partition)
            raise CertificateNotFoundError()
        else:
            raise
    try:
        os.remove(cert_name)
    except OSError as error:
        if error.errno == 2:
            logger.debug('Did not find cert %s from partition %s in the cert folder',
                         name, partition)
            failures += 1
        else:
            raise
    try:
        os.remove(uninstalled_cert_name)
    except OSError as error:
        if error.errno == 2:
            logger.debug('Did not find cert %s from partition %s in the to_be_installed folder',
                         name, partition)
            failures += 1
        else:
            raise
    if failures > 1:
        logger.error("The CSR for certificate %s in partition %s was found, but not the cert",
                     name, partition)

