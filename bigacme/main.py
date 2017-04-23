"""The main program"""
import os
import sys
import errno
import getpass
import argparse
import logging
import logging.config

from ConfigParser import NoSectionError, NoOptionError
from acme import errors as acme_errors

from . import config
from . import cert
from . import ca
from . import lb
from . import version

# pylint: disable=W0613

logger = logging.getLogger(__name__)


def main():
    """Parses the parameters and calls the right function"""
    parser = argparse.ArgumentParser(description='ACME client for Big-IP')
    parser.add_argument('--config-dir', default=".",
                        help="The config dir to use. Defaults to the current folder")
    subparsers = parser.add_subparsers(help="The operation you want to do:", dest="operation")

    parser_new = subparsers.add_parser(
        "new", help="Request a new certificate")
    parser_new.add_argument("partition", help="The name of partition on the Big-IP")
    parser_new.add_argument("csrname", help="The name of the csr on the Big-IP")
    parser_new.set_defaults(func=new_cert)

    parser_remove = subparsers.add_parser(
        "remove", help="Removes a certificate, so that it won't be renewd")
    parser_remove.add_argument("partition", help="The name of partition on the Big-IP")
    parser_remove.add_argument("csrname", help="The name of the csr on the Big-IP")
    parser_remove.set_defaults(func=remove)

    parser_revoke = subparsers.add_parser(
        "revoke", help="Revokes a certificate")
    parser_revoke.add_argument("partition", help="The name of partition on the Big-IP")
    parser_revoke.add_argument("csrname", help="The name of the csr on the Big-IP")
    parser_revoke.set_defaults(func=revoke)

    parser_renew = subparsers.add_parser(
        "renew", help="Renew existing certificates")
    parser_renew.set_defaults(func=renew)

    parser_test = subparsers.add_parser(
        "test", help="Test connectivity to the CA and the load balancer")
    parser_test.set_defaults(func=test)

    parser_register = subparsers.add_parser(
        "register", help="Generates an account key and registers it with the specified CA")
    parser_register.set_defaults(func=register)

    parser_config = subparsers.add_parser(
        "config", help="Generate a folder structure with config files")
    parser_config.set_defaults(func=new_config)

    parser_config = subparsers.add_parser(
        "version", help="Prints the version number and exits.")
    parser_config.set_defaults(func=print_version)

    args = parser.parse_args()
    try:
        os.chdir(os.path.abspath(args.config_dir))
    except OSError as error:
        if error.errno == 2:
            sys.exit("Could not locate the specified configuration folder")
        else:
            raise
    if args.operation not in ['config', 'version']:
        if not config.check_configfiles():
            sys.exit("Could not find the configuration files in the specified folder")
        logging.config.fileConfig("./config/logging.ini", disable_existing_loggers=False)
        try:
            the_config = config.read_configfile('./config/config.ini')
        except (NoSectionError, NoOptionError, ValueError) as error:
            sys.exit(("The configuration files was found, but was not complete. "
                      "The error was: %s" % error.message))
    else:
        the_config = None
    try:
        args.func(args, the_config)
    except Exception: # pylint: disable=W0703
        logger.exception('An exception occured:')
        sys.exit("An unexpected error occured. Check the log for the details")

def new_cert(args, configuration):
    """Fetches the specified CSR from the device and retrieves a certificate from the CA"""
    logger.info('User %s started issuance of cert %s in partition %s', getpass.getuser(),
                args.csrname, args.partition)
    bigip = lb.connect(configuration)
    print "Getting the CSR from the Big-IP..."
    try:
        csr = lb.get_csr(bigip, args.partition, args.csrname)
    except lb.PartitionNotFoundError:
        logger.error("The partition was not found on the device")
        sys.exit("The specified partition does not seem to exist.")
    except lb.AccessDeniedError:
        logger.error("The user was denied access by the load balancer")
        sys.exit("The user was denied access by the load balancer. "
                 "Do the user have the Certificate Manager role in the specified partition?")
    except lb.NotFoundError:
        logger.error("The CSR was not found on the device")
        sys.exit('Could not find the csr on the big-ip. Check the spelling.')

    logger.debug('Saving the csr to disk')
    cert.save_csr_to_disk(args.partition, args.csrname, csr)

    print "Getting a new certificate from the CA. This may take a while..."
    try:
        certificate = _get_new_cert(csr, bigip, args.partition, args.csrname, configuration)
    except ca.GetCertificateFailedError as error:
        logger.error("Could not get a certificate from the CA. The error was: %s", error.message)
        sys.exit(("Could not get a certificate from the CA. Is the iRule attached to the "
                  "Virtual Server? The error was: %s" % error.message))
    cert.save_cert_to_disk(args.partition, args.csrname, certificate)
    lb.upload_certificate(bigip, args.partition, args.csrname, certificate)
    print "Done."

def renew(args, configuration):
    """Goes through all the issued certs and renews them if needed"""
    logger.info('Starting renewal')
    bigip = lb.connect(configuration)

    renewals = cert.check_for_renewals(configuration)
    for renewal in renewals:
        csr = cert.load_associated_csr(renewal)
        partition, name = cert.get_name_from_filename(renewal)
        logger.info('Renewing cert: %s from partition: %s', name, partition)
        try:
            certificate = _get_new_cert(csr, bigip, partition, name, configuration)
        except ca.GetCertificateFailedError:
            logger.exception("Could not renew certificate %s in partition %s:", name, partition)
            continue
        except lb.LoadBalancerError:
            logger.exception("Could not renew certificate %s in partition %s:", name, partition)
            continue
        cert.save_renewed_cert_to_disk(partition, name, certificate)
        cert.move_cert_to_backup(renewal)

    certs_to_be_installed = cert.get_certificate_to_be_installed(configuration)
    for to_be_installed_cert in certs_to_be_installed:
        partition, name = cert.get_name_from_filename(to_be_installed_cert)
        logger.info('Installing cert: %s in partition: %s', name, partition)
        renewed_cert = cert.load_renewed_cert_from_disk(partition, name)
        try:
            lb.upload_certificate(bigip, partition, name, renewed_cert)
        except lb.LoadBalancerError:
            logger.exception("Could not install certificate %s in partition %s:", name, partition)
            continue
        cert.move_renewed_cert(to_be_installed_cert)

    cert.delete_expired_backups()
    logger.info('Renewal completed')

def remove(args, configuration):
    """Removes a certificate so that it won't get renewed"""
    logger.info('User %s started removing cert %s in partition %s', getpass.getuser(),
                args.csrname, args.partition)
    try:
        cert.remove_cert(args.partition, args.csrname)
    except cert.CertificateNotFoundError:
        sys.exit("The specified certificate was not found")

def revoke(args, configuration):
    """Revokes a certificate"""
    print "This will REVOKE the specified certificate. It will no longer be usable.\r\n"
    print ("You should ONLY do this if the private key has been compromised. It is not "
           "necessary if the certificate is just beeing retired.")
    print "Are you sure you want to continue? Type REVOKE (all caps) if you are sure."

    choice = raw_input()
    if choice != 'REVOKE':
        sys.exit('Exiting...')

    choice = ''
    while choice not in ('0', '1', '3', '4', '5'):
        print "What is the reason you are revoking this cert?"
        print "0) Unspecified"
        print "1) Key compromise"
        print "3) Affiliation changed"
        print "4) Superseded"
        print "5) Cessation of operation"
        choice = raw_input().replace(')', '')
    reason = int(choice)

    logger.info('User %s started revoking cert %s in partition %s', getpass.getuser(),
                args.csrname, args.partition)
    try:
        certificate = cert.load_cert_from_disk(args.partition, args.csrname)
    except cert.CertificateNotFoundError:
        sys.exit("The specified certificate was not found.")

    key = config.get_account_key(configuration)
    acme_client = ca.get_client(configuration, key)
    ca.revoke_certifciate(configuration, acme_client, certificate, reason)
    cert.remove_cert(args.partition, args.csrname)
    print "Certificate %s in partition %s revoked" % (args.csrname, args.partition)

def test(args, configuration):
    """Tests the connections to the load balancer and the ca"""
    try:
        lb.connect(configuration)
    except: # pylint: disable=W0702
        print "Could not connect to the load balancer. Check the log."
        logger.exception("Could not connect to the load balancer:")
    else:
        print "The connection to the load balancer was successfull"
    try:
        ca.get_client(configuration, None)
    except: # pylint: disable=W0702
        print "Could not connect to the CA. Check the log."
        logger.exception("Could not connect to the CA:")
    else:
        print "The connection to the CA was successfull"

def print_version(args, configuration):
    """Prints the version number and exits"""
    print version.__version__

def register(args, configuration):
    """Genereates a account key, and registeres with the specified CA"""
    print "This will generate an account key and register it with the specified CA."
    print "Do you want to continue? yes or no"
    choice = raw_input().lower()
    if choice != 'yes' and choice != 'y':
        sys.exit('User did not want to continue. Exiting')
    print "What mail address do you want to register with the account key?"
    mail = raw_input().lower()
    print "You typed in %s, is this correct? yes or no" % mail
    choice2 = raw_input().lower()
    if choice2 != 'yes' and choice2 != 'y':
        sys.exit('Wrong mail. Exiting')

    try:
        key = config.create_account_key(configuration)
    except config.KeyAlreadyExistsError:
        sys.exit("Key file already exists. You can not register a key twice. \r\n"
                 "You must delete it to register again.")
    acme_client = ca.get_client(configuration, key)
    try:
        ca.register_with_ca(configuration, acme_client, mail)
    except acme_errors.Error as error:
        logger.exception("Failed to register with the CA:")
        sys.exit('The registration failed. The error was: %s' % error)

def new_config(args, configuration):
    """Creates the enviroment with configuration files and folders"""
    props_file = './config/config.ini'
    log_file = './config/logging.ini'
    print("This will create the necessary folder structure, and configuration files "
          "in the specified configuration folder (default is the current folder)")
    print "Do you want to continue? yes or no"
    choice = raw_input().lower()
    if choice != 'yes' and choice != 'y':
        sys.exit('User did not want to continue. Exiting')
    folders = ["config", "cert", "csr", "cert/backup", "cert/to_be_installed"]
    for folder in folders:
        try:
            os.makedirs(folder)
        except OSError as error:
            if (error.errno == errno.EEXIST and
                    os.path.isdir(folder)):
                print "The folder %s already exists" % folder
            else:
                raise
    if not os.path.exists(props_file):
        config.create_configfile(props_file)
    else:
        print "The config file already exists. Not touching it"
    if not os.path.exists(log_file):
        config.create_logconfigfile(log_file)
    else:
        print "The logging config file already exists. Not touching it"
    print "Done! Adjust the configuration files as needed"

def _get_new_cert(csr, bigip, partition, name, configuration):
    key = config.get_account_key(configuration)
    acme_client = ca.get_client(configuration, key)

    hostnames = cert.get_hostnames_from_csr(csr)
    logger.debug("The csr has the following hostnames: %s", hostnames)
    logger.debug("Getting the challenges from the CA")
    challenges, authz = ca.get_http_challenge_for_domains(configuration,
                                                          acme_client,
                                                          hostnames,
                                                          key)

    for challenge in challenges:
        lb.send_challenge(bigip, challenge.domain, challenge.path, challenge.validation,
                          configuration)

    ca.answer_challenges(configuration, acme_client, challenges)
    certificate, chain = ca.get_certificate_from_ca(configuration, acme_client, csr, authz)

    for challenge in challenges:
        lb.remove_challenge(bigip, challenge.domain, challenge.path, configuration)
    cert_with_chain = certificate
    if configuration.cm_chain:
        for chain_cert in chain:
            cert_with_chain += chain_cert
    return cert_with_chain
