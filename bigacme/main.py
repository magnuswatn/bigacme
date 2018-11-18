"""The main program"""
import os
import sys
import errno
import getpass
import datetime
import argparse
import logging
import logging.config

from configparser import NoSectionError, NoOptionError
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
    parser = argparse.ArgumentParser(description="ACME client for Big-IP")
    parser.add_argument(
        "--config-dir",
        default=".",
        help="the config dir to use. Defaults to the current folder",
    )
    subparsers = parser.add_subparsers(
        help="The operation you want to do:", dest="operation"
    )
    subparsers.required = True

    parser_new = subparsers.add_parser("new", help="request a new certificate")
    parser_new.add_argument("partition", help="the name of partition on the Big-IP")
    parser_new.add_argument("csrname", help="the name of the csr on the Big-IP")
    parser_new.add_argument(
        "-dns", help="Use DNS validation instead of HTTP", action="store_true"
    )
    parser_new.set_defaults(func=new_cert)

    parser_remove = subparsers.add_parser(
        "remove", help="remove a certificate, so that it won't be renewd"
    )
    parser_remove.add_argument("partition", help="the name of partition on the Big-IP")
    parser_remove.add_argument("csrname", help="the name of the csr on the Big-IP")
    parser_remove.set_defaults(func=remove)

    parser_revoke = subparsers.add_parser("revoke", help="revoke a certificate")
    parser_revoke.add_argument("partition", help="the name of partition on the Big-IP")
    parser_revoke.add_argument("csrname", help="the name of the csr on the Big-IP")
    parser_revoke.set_defaults(func=revoke)

    parser_renew = subparsers.add_parser("renew", help="renew existing certificates")
    parser_renew.set_defaults(func=renew)

    parser_test = subparsers.add_parser(
        "test", help="test connectivity to the CA and the load balancer"
    )
    parser_test.set_defaults(func=test)

    parser_register = subparsers.add_parser(
        "register", help="generate an account key and register it with the CA"
    )
    parser_register.set_defaults(func=register)

    parser_config = subparsers.add_parser(
        "config", help="generate a folder structure with config files"
    )
    parser_config.add_argument(
        "-debug",
        help="Create logging config with DEBUG for bigacme",
        action="store_true",
    )
    parser_config.set_defaults(func=new_config)

    parser_list = subparsers.add_parser(
        "list", help="list all the certificates that will be renewed"
    )
    parser_list.add_argument(
        "partition", help="the name of partition on the Big-IP", nargs="?"
    )
    parser_list.set_defaults(func=list_certs)

    parser_version = subparsers.add_parser(
        "version", help="show the version number and exit"
    )
    parser_version.set_defaults(func=print_version)

    args = parser.parse_args()
    try:
        os.chdir(os.path.abspath(args.config_dir))
    except OSError as error:
        if error.errno == 2:
            sys.exit("Could not locate the specified configuration folder")
        else:
            raise
    if args.operation not in ["config", "version"]:
        if not config.check_configfiles():
            sys.exit("Could not find the configuration files in the specified folder")

        if args.operation not in ["register", "test"]:
            if not config.check_account_file():
                sys.exit("Could not find an account. You must register with the CA.")

        logging.config.fileConfig(
            config.LOG_CONFIG_FILE, disable_existing_loggers=False
        )

        try:
            the_config = config.read_configfile()
        except (NoSectionError, NoOptionError, ValueError) as error:
            sys.exit(
                (
                    "The configuration files was found, but was not complete. "
                    f"The error was: {error}"
                )
            )
    else:
        the_config = None

    try:
        args.func(args, the_config)
    except Exception:  # pylint: disable=W0703
        logger.exception("An exception occured:")
        sys.exit("An unexpected error occured. Check the log for the details")


def new_cert(args, configuration):
    """Fetches the specified CSR from the device and retrieves a certificate from the CA"""
    logger.info(
        "User %s started issuance of cert %s in partition %s",
        getpass.getuser(),
        args.csrname,
        args.partition,
    )
    bigip = lb.LoadBalancer(configuration)

    if args.dns:
        try:
            dns_plugin = plugin.get_plugin(configuration)
        except plugin.NoPluginFoundError:
            logger.error(
                "No DNS plugin was found. "
                "Unable to get certificate by using DNS validation without plugin."
            )
            sys.exit(
                "No DNS plugin was found. A DNS plugin is needed for DNS validation."
            )

        except plugin.InvalidConfigError as error:
            logger.exception("Failed to initialize plugin. Error was: %s", error)
            sys.exit(f"Failed to initialize plugin. Error was: {error}")

        chall_typ = "dns-01"
    else:
        dns_plugin = None
        chall_typ = "http-01"

    print("Getting the CSR from the Big-IP...")

    try:
        with click_spinner.spinner():
            csr = bigip.get_csr(args.partition, args.csrname)
    except lb.PartitionNotFoundError:
        logger.error("The partition was not found on the device")
        sys.exit("The specified partition does not seem to exist.")
    except lb.AccessDeniedError:
        logger.error("The user was denied access by the load balancer")
        sys.exit(
            "The user was denied access by the load balancer. "
            "Do the user have the Certificate Manager role in the specified partition?"
        )
    except lb.NotFoundError:
        logger.error("The CSR was not found on the device")
        sys.exit("Could not find the csr on the big-ip. Check the spelling.")

    certobj = cert.Certificate.new(args.partition, args.csrname, csr, chall_typ)
    print("Getting a new certificate from the CA. This may take a while...")
    acme_ca = ca.CertificateAuthority(configuration)

    try:
        with click_spinner.spinner():
            certificate = _get_new_cert(acme_ca, bigip, certobj, dns_plugin)
    except ca.GetCertificateFailedError as error:
        logger.error(
            "Could not get a certificate from the CA. The error was: %s", error
        )
        if chall_typ == "http-01":
            sys.exit(
                (
                    "Could not get a certificate from the CA. Is the iRule attached to the "
                    f"Virtual Server? The error was: {error}"
                )
            )
        else:
            sys.exit(f"Could not get a certificate from the CA. The error was: {error}")
    except plugin.PluginError as error:
        logger.exception("An error occured in %s:", dns_plugin.name)
        sys.exit(f"An error occured while solving the challenge(s): {error}")

    certobj.cert = certificate
    bigip.upload_certificate(args.partition, args.csrname, certobj.cert)
    certobj.mark_as_installed()
    print("Done.")


def renew(args, configuration):
    """Goes through all the issued certs and renews them if needed"""
    logger.info("Starting renewal process")
    renewals, certs_to_be_installed = cert.get_certs_that_need_action(configuration)

    if renewals or certs_to_be_installed:
        acme_ca = ca.CertificateAuthority(configuration)
        bigip = lb.LoadBalancer(configuration)

    dns_plugin = None
    for renewal in renewals:
        logger.info(
            "Renewing cert: %s from partition: %s using %s",
            renewal.name,
            renewal.partition,
            renewal.validation_method,
        )

        if renewal.validation_method == "dns-01" and not dns_plugin:
            try:
                dns_plugin = plugin.get_plugin(configuration)
            except plugin.PluginError:
                logger.exception(
                    "Could not load plugin to renew certificate %s in partition %s:",
                    renewal.name,
                    renewal.partition,
                )
                continue

        try:
            certificate = _get_new_cert(acme_ca, bigip, renewal, dns_plugin)
        except (ca.GetCertificateFailedError, lb.LoadBalancerError, plugin.PluginError):
            logger.exception(
                "Could not renew certificate %s in partition %s:",
                renewal.name,
                renewal.partition,
            )
            continue
        renewal.renew(certificate)

    for tbi_cert in certs_to_be_installed:
        logger.info(
            "Installing cert: %s in partition: %s", tbi_cert.name, tbi_cert.partition
        )
        try:
            bigip.upload_certificate(tbi_cert.partition, tbi_cert.name, tbi_cert.cert)
        except lb.LoadBalancerError:
            logger.exception(
                "Could not install certificate %s in partition %s:",
                tbi_cert.name,
                tbi_cert.partition,
            )
            continue
        tbi_cert.mark_as_installed()

    cert.delete_expired_backups()
    logger.info("Renewal process completed")


def remove(args, configuration):
    """Removes a certificate so that it won't get renewed"""
    try:
        cert.Certificate.get(args.partition, args.csrname).delete()
    except cert.CertificateNotFoundError:
        sys.exit("The specified certificate was not found")
    logger.info(
        "User %s removed cert %s in partition %s",
        getpass.getuser(),
        args.csrname,
        args.partition,
    )
    print(f"Certificate {args.csrname} in partition {args.partition} removed")


def revoke(args, configuration):
    """Revokes a certificate"""

    try:
        certificate = cert.Certificate.get(args.partition, args.csrname)
    except cert.CertificateNotFoundError:
        sys.exit("The specified certificate was not found.")

    print(
        "This will REVOKE the specified certificate. It will no longer be usable.\r\n"
    )
    print(
        "You should ONLY do this if the private key has been compromised. It is not "
        "necessary if the certificate is just beeing retired."
    )
    print("Are you sure you want to continue? Type REVOKE (all caps) if you are sure.")

    choice = input()
    if choice != "REVOKE":
        sys.exit("Exiting...")

    choice = ""
    while choice not in ("0", "1", "3", "4", "5"):
        print("What is the reason you are revoking this cert?")
        print("0) Unspecified")
        print("1) Key compromise")
        print("3) Affiliation changed")
        print("4) Superseded")
        print("5) Cessation of operation")
        choice = input().replace(")", "")
    reason = int(choice)

    acme_ca = ca.CertificateAuthority(configuration)
    acme_ca.revoke_certifciate(certificate.cert, reason)
    certificate.delete()
    logger.info(
        "User %s revoked cert %s in partition %s",
        getpass.getuser(),
        args.csrname,
        args.partition,
    )
    print(f"Certificate {args.csrname} in partition {args.partition} revoked")


def test(args, configuration):
    """Tests the connections to the load balancer and the ca"""
    try:
        lb.LoadBalancer(configuration)
    except:  # pylint: disable=W0702
        print("Could not connect to the load balancer. Check the log.")
        logger.exception("Could not connect to the load balancer:")
    else:
        print("The connection to the load balancer was successfull")
    try:
        ca.CertificateAuthority(configuration)
    except:  # pylint: disable=W0702
        print("Could not connect to the CA. Check the log.")
        logger.exception("Could not connect to the CA:")
    else:
        print("The connection to the CA was successfull")


def print_version(args, configuration):
    """Prints the version number and exits"""
    print(version.__version__)


def register(args, configuration):
    """Genereates a account key, and registeres with the specified CA"""
    acme_ca = ca.CertificateAuthority(configuration)
    if acme_ca.key:
        sys.exit("Account config already exists - already registered?")

    print("This will generate an account key and register it with the specified CA.")
    print("Do you want to continue? yes or no")
    choice = input().lower()
    if choice not in ["y", "ya", "yes", "yass"]:
        sys.exit("OK. Bye bye.")

    if "terms_of_service" in acme_ca.client.directory.meta:
        print(
            f"Do you agree with the terms of service, as described at "
            f"{acme_ca.client.directory.meta.terms_of_service}?"
        )
        choice2 = input().lower()
        if choice2 not in ["y", "ya", "yes", "yass"]:
            sys.exit("You must agree to the terms of service to register.")

    print("What mail address do you want to register with the account?")
    mail = input().lower()

    print(f"You typed in {mail}, is this correct? yes or no.")
    choice3 = input().lower()
    if choice3 not in ["y", "ya", "yes", "yass"]:
        sys.exit("Wrong mail. Exiting")

    try:
        acme_ca.register(mail)
    except acme_errors.Error as error:
        logger.exception("Failed to register with the CA:")
        sys.exit(f"The registration failed. The error was: {error}")
    print("Registration successful")


def new_config(args, configuration):
    """Creates the enviroment with configuration files and folders"""
    print(
        "This will create the necessary folder structure, and configuration files "
        "in the specified configuration folder (default is the current folder)"
    )
    print("Do you want to continue? yes or no")

    choice = input().lower()
    if choice != "yes" and choice != "y":
        sys.exit("User did not want to continue. Exiting")

    for folder in config.CONFIG_DIRS:
        try:
            os.makedirs(folder)
        except OSError as error:
            if error.errno == errno.EEXIST and os.path.isdir(folder):
                print(f"The folder {folder} already exists.")
            else:
                raise

    if not os.path.exists(config.CONFIG_FILE):
        config.create_configfile()
    else:
        print("The config file already exists. Not touching it")

    if not os.path.exists(config.LOG_CONFIG_FILE):
        config.create_logconfigfile(args.debug)
    else:
        print("The logging config file already exists. Not touching it")

    print("Done! Adjust the configuration files as needed")


def list_certs(args, configuration):
    """Lists all the certs that are going to be renewed"""
    columns = ("Partition", "Name", "Validation method", "Status")
    all_certs = cert.get_all_certs()
    relevant_certs = []
    for certificate in all_certs:
        if args.partition and args.partition != certificate.partition:
            continue
        relevant_certs.append(
            (
                certificate.partition,
                certificate.name,
                certificate.validation_method,
                certificate.status,
            )
        )
    relevant_certs.sort()
    if relevant_certs:
        _print_table(columns, relevant_certs)
    else:
        print("No certificates found")


def _print_table(headers, values):
    """Prints an OK (ish) ascii table"""
    max_widths = [len(str(x)) for x in headers]
    for value in values:
        max_widths = [max(x, len(str(y))) for x, y in zip(max_widths, value)]

    header = [str(c).ljust(w) for w, c in zip(max_widths, headers)]
    separator = ["-" * x for x in max_widths]

    print("+ {} +".format(" + ".join(list(separator))))
    print("| {} |".format(" | ".join(list(header))))
    print("+ {} +".format(" + ".join(list(separator))))

    for value in values:
        cols = [str(c).ljust(w) for w, c in zip(max_widths, value)]
        print("| {} |".format(" | ".join(list(cols))))

    print("+ {} +".format(" + ".join(list(separator))))


def _get_new_cert(acme_ca, bigip, csr, dns_plugin):
    logger.debug("Getting the challenges from the CA")

    order = acme_ca.order_new_cert(csr.csr)
    challenges = acme_ca.get_challenges_from_order(order, csr.validation_method)

    if csr.validation_method == "http-01":
        for challenge in challenges:
            bigip.send_challenge(
                challenge.domain, challenge.challenge.path, challenge.validation
            )
    elif csr.validation_method == "dns-01":
        for challenge in challenges:
            record_name = challenge.challenge.validation_domain_name(challenge.domain)
            dns_plugin.perform(challenge.domain, record_name, challenge.validation)
        dns_plugin.finish_perform()
    else:
        raise ca.UnknownValidationType(
            f"Validation type {csr.validation_method} is not recognized"
        )

    acme_ca.answer_challenges(challenges)
    try:
        certificate = acme_ca.get_certificate_from_ca(order)
    finally:
        # cleanup
        if csr.validation_method == "http-01":
            for challenge in challenges:
                bigip.remove_challenge(challenge.domain, challenge.challenge.path)
        elif csr.validation_method == "dns-01":
            for challenge in challenges:
                record_name = challenge.challenge.validation_domain_name(
                    challenge.domain
                )
                dns_plugin.cleanup(challenge.domain, record_name, challenge.validation)
            dns_plugin.finish_cleanup()

    return certificate
