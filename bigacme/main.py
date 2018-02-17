"""The main program"""
from __future__ import print_function

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
from . import plugin
from . import version
from .vendor import click_spinner

# pylint: disable=W0613

logger = logging.getLogger(__name__)

def main():
    """Parses the parameters and calls the right function"""
    parser = argparse.ArgumentParser(description='ACME client for Big-IP')
    parser.add_argument('--config-dir', default=".",
                        help="the config dir to use. Defaults to the current folder")
    subparsers = parser.add_subparsers(help="The operation you want to do:", dest="operation")

    parser_new = subparsers.add_parser(
        "new", help="request a new certificate")
    parser_new.add_argument("partition", help="the name of partition on the Big-IP")
    parser_new.add_argument("csrname", help="the name of the csr on the Big-IP")
    parser_new.add_argument("-dns", help="Use DNS validation instead of HTTP", action='store_true')
    parser_new.set_defaults(func=new_cert)

    parser_remove = subparsers.add_parser(
        "remove", help="remove a certificate, so that it won't be renewd")
    parser_remove.add_argument("partition", help="the name of partition on the Big-IP")
    parser_remove.add_argument("csrname", help="the name of the csr on the Big-IP")
    parser_remove.set_defaults(func=remove)

    parser_revoke = subparsers.add_parser(
        "revoke", help="revoke a certificate")
    parser_revoke.add_argument("partition", help="the name of partition on the Big-IP")
    parser_revoke.add_argument("csrname", help="the name of the csr on the Big-IP")
    parser_revoke.set_defaults(func=revoke)

    parser_renew = subparsers.add_parser(
        "renew", help="renew existing certificates")
    parser_renew.set_defaults(func=renew)

    parser_test = subparsers.add_parser(
        "test", help="test connectivity to the CA and the load balancer")
    parser_test.set_defaults(func=test)

    parser_register = subparsers.add_parser(
        "register", help="generate an account key and register it with the CA")
    parser_register.set_defaults(func=register)

    parser_config = subparsers.add_parser(
        "config", help="generate a folder structure with config files")
    parser_config.add_argument("-debug", help="Create logging config with DEBUG for bigacme",
                               action='store_true')
    parser_config.set_defaults(func=new_config)

    parser_config = subparsers.add_parser("version", help="show the version number and exit")
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

        logging.config.fileConfig(config.LOG_CONFIG_FILE, disable_existing_loggers=False)

        try:
            the_config = config.read_configfile()
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
    bigip = lb.LoadBalancer(configuration)

    if args.dns:
        try:
            dns_plugin = plugin.get_plugin(configuration)
        except plugin.NoPluginFoundError:
            logger.error("No DNS plugin was found. "
                         "Unable to get certificate by using DNS validation without plugin.")
            sys.exit("No DNS plugin was found. A DNS plugin is needed for DNS validation.")

        except plugin.InvalidConfigError as error:
            logger.exception("Failed to initialize plugin. Error was: %s", error.message)
            sys.exit("Failed to initialize plugin. Error was: %s" % error.message)

        chall_typ = 'dns-01'
    else:
        dns_plugin = None
        chall_typ = 'http-01'

    print('Getting the CSR from the Big-IP...')

    try:
        with click_spinner.spinner():
            csr = bigip.get_csr(args.partition, args.csrname)
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

    certobj = cert.Certificate.new(args.partition, args.csrname, csr, chall_typ)
    print('Getting a new certificate from the CA. This may take a while...')
    acme_ca = ca.CertificateAuthority(configuration)

    try:
        with click_spinner.spinner():
            certificate, chain = _get_new_cert(acme_ca, bigip, certobj, dns_plugin)
    except ca.GetCertificateFailedError as error:
        logger.error("Could not get a certificate from the CA. The error was: %s", error.message)
        if chall_typ == 'http-01':
            sys.exit(("Could not get a certificate from the CA. Is the iRule attached to the "
                      "Virtual Server? The error was: %s" % error.message))
        else:
            sys.exit(("Could not get a certificate from the CA. The error was: %s" % error.message))
    except plugin.PluginError as error:
        logger.exception('An error occured in %s:', dns_plugin.name)
        sys.exit('An error occured while solving the challenge(s): %s' % error)

    certobj.cert, certobj.chain = certificate, chain
    bigip.upload_certificate(args.partition, args.csrname, certobj.get_pem(configuration.cm_chain))
    certobj.mark_as_installed()
    print('Done.')

def renew(args, configuration):
    """Goes through all the issued certs and renews them if needed"""
    logger.info('Starting renewal process')
    renewals, certs_to_be_installed = cert.get_certs_that_need_action(configuration)

    if renewals or certs_to_be_installed:
        acme_ca = ca.CertificateAuthority(configuration)
        bigip = lb.LoadBalancer(configuration)

    dns_plugin = None
    for renewal in renewals:
        logger.info('Renewing cert: %s from partition: %s using %s',
                    renewal.name, renewal.partition, renewal.validation_method)

        if renewal.validation_method == 'dns-01' and not dns_plugin:
            try:
                dns_plugin = plugin.get_plugin(configuration)
            except plugin.PluginError:
                logger.exception("Could not load plugin to renew certificate %s in partition %s:",
                                 renewal.name, renewal.partition)
                continue

        try:
            certificate, chain = _get_new_cert(acme_ca, bigip, renewal, dns_plugin)
        except (ca.GetCertificateFailedError, lb.LoadBalancerError, plugin.PluginError):
            logger.exception("Could not renew certificate %s in partition %s:",
                             renewal.name, renewal.partition)
            continue
        renewal.renew(certificate, chain)

    for tbi_cert in certs_to_be_installed:
        logger.info('Installing cert: %s in partition: %s', tbi_cert.name, tbi_cert.partition)
        try:
            bigip.upload_certificate(tbi_cert.partition, tbi_cert.name,
                                     tbi_cert.get_pem(configuration.cm_chain))
        except lb.LoadBalancerError:
            logger.exception("Could not install certificate %s in partition %s:",
                             tbi_cert.name, tbi_cert.partition)
            continue
        tbi_cert.mark_as_installed()

    cert.delete_expired_backups()
    logger.info('Renewal process completed')

def remove(args, configuration):
    """Removes a certificate so that it won't get renewed"""
    try:
        cert.Certificate.get(args.partition, args.csrname).delete()
    except cert.CertificateNotFoundError:
        sys.exit("The specified certificate was not found")
    logger.info('User %s removed cert %s in partition %s', getpass.getuser(),
                args.csrname, args.partition)
    print('Certificate {} in partition {} removed'.format(args.csrname, args.partition))

def revoke(args, configuration):
    """Revokes a certificate"""
    print('This will REVOKE the specified certificate. It will no longer be usable.\r\n')
    print('You should ONLY do this if the private key has been compromised. It is not '
          'necessary if the certificate is just beeing retired.')
    print('Are you sure you want to continue? Type REVOKE (all caps) if you are sure.')

    choice = raw_input()
    if choice != 'REVOKE':
        sys.exit('Exiting...')

    choice = ''
    while choice not in ('0', '1', '3', '4', '5'):
        print('What is the reason you are revoking this cert?')
        print('0) Unspecified')
        print('1) Key compromise')
        print('3) Affiliation changed')
        print('4) Superseded')
        print('5) Cessation of operation')
        choice = raw_input().replace(')', '')
    reason = int(choice)

    try:
        certificate = cert.Certificate.get(args.partition, args.csrname)
    except cert.CertificateNotFoundError:
        sys.exit("The specified certificate was not found.")

    acme_ca = ca.CertificateAuthority(configuration)
    acme_ca.revoke_certifciate(certificate.cert, reason)
    certificate.delete()
    logger.info('User %s revoked cert %s in partition %s', getpass.getuser(),
                args.csrname, args.partition)
    print('Certificate {} in partition {} revoked'.format(args.csrname, args.partition))

def test(args, configuration):
    """Tests the connections to the load balancer and the ca"""
    try:
        lb.LoadBalancer(configuration)
    except: # pylint: disable=W0702
        print('Could not connect to the load balancer. Check the log.')
        logger.exception("Could not connect to the load balancer:")
    else:
        print('The connection to the load balancer was successfull')
    try:
        ca.CertificateAuthority(configuration, test=True)
    except: # pylint: disable=W0702
        print('Could not connect to the CA. Check the log.')
        logger.exception("Could not connect to the CA:")
    else:
        print('The connection to the CA was successfull')

def print_version(args, configuration):
    """Prints the version number and exits"""
    print(version.__version__)

def register(args, configuration):
    """Genereates a account key, and registeres with the specified CA"""
    print('This will generate an account key and register it with the specified CA.')
    print('Do you want to continue? yes or no')
    choice = raw_input().lower()
    if choice != 'yes' and choice != 'y':
        sys.exit('User did not want to continue. Exiting')
    print('What mail address do you want to register with the account key?')
    mail = raw_input().lower()
    print('You typed in {}, is this correct? yes or no'.format(mail))
    choice2 = raw_input().lower()
    if choice2 != 'yes' and choice2 != 'y':
        sys.exit('Wrong mail. Exiting')

    try:
        config.create_account_key(configuration)
    except config.KeyAlreadyExistsError:
        sys.exit("Key file already exists. You can not register a key twice. \r\n"
                 "You must delete it to register again.")
    acme_ca = ca.CertificateAuthority(configuration)
    try:
        acme_ca.register(mail)
    except acme_errors.Error as error:
        config.delete_account_key(configuration)
        logger.exception('Failed to register with the CA:')
        sys.exit('The registration failed. The error was: %s' % error)
    print('Registration successful')

def new_config(args, configuration):
    """Creates the enviroment with configuration files and folders"""
    print('This will create the necessary folder structure, and configuration files '
          'in the specified configuration folder (default is the current folder)')
    print('Do you want to continue? yes or no')

    choice = raw_input().lower()
    if choice != 'yes' and choice != 'y':
        sys.exit('User did not want to continue. Exiting')

    for folder in config.CONFIG_DIRS:
        try:
            os.makedirs(folder)
        except OSError as error:
            if (error.errno == errno.EEXIST and
                    os.path.isdir(folder)):
                print('The folder {} already exists'.format(folder))
            else:
                raise

    if not os.path.exists(config.CONFIG_FILE):
        config.create_configfile()
    else:
        print('The config file already exists. Not touching it')

    if not os.path.exists(config.LOG_CONFIG_FILE):
        config.create_logconfigfile(args.debug)
    else:
        print('The logging config file already exists. Not touching it')

    print('Done! Adjust the configuration files as needed')

def _get_new_cert(acme_ca, bigip, csr, dns_plugin):
    logger.debug("The csr has the following hostnames: %s", csr.hostnames)
    logger.debug("Getting the challenges from the CA")

    challenges, authz = acme_ca.get_challenge_for_domains(csr.hostnames, csr.validation_method)

    if csr.validation_method == 'http-01':
        for challenge in challenges:
            bigip.send_challenge(challenge.domain, challenge.challenge.path, challenge.validation)
    elif csr.validation_method == 'dns-01':
        for challenge in challenges:
            record_name = challenge.challenge.validation_domain_name(challenge.domain)
            dns_plugin.perform(challenge.domain, record_name, challenge.validation)
        dns_plugin.finish_perform()
    else:
        raise ca.UnknownValidationType('Validation type %s is not recognized' %
                                       csr.validation_method)

    acme_ca.answer_challenges(challenges)
    try:
        certificate, chain = acme_ca.get_certificate_from_ca(csr.csr, authz)
    finally:
        # cleanup
        if csr.validation_method == 'http-01':
            for challenge in challenges:
                bigip.remove_challenge(challenge.domain, challenge.challenge.path)
        elif csr.validation_method == 'dns-01':
            for challenge in challenges:
                record_name = challenge.challenge.validation_domain_name(challenge.domain)
                dns_plugin.cleanup(challenge.domain, record_name, challenge.validation)
            dns_plugin.finish_cleanup()

    return certificate, chain
