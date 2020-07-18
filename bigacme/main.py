"""The main program"""
import errno
import getpass
import logging
import logging.config
import os
import sys
from configparser import NoOptionError, NoSectionError

import click
from acme import errors as acme_errors

from . import ca, cert, config, lb, plugin, utils, version
from .vendor import click_spinner

# pylint: disable=W0613

logger = logging.getLogger(__name__)


def partition_completer(ctx, args, incomplete):
    # disable logging  so we don't spam
    # stdout with logging if something goes
    # kinda wrong
    logging.disable(60)
    try:
        all_certs = cert.get_all_certs()
        partitions = set(
            [x.partition for x in all_certs if x.partition.startswith(incomplete)]
        )
        return sorted(partitions)
    except:
        return []


def csrname_completer(ctx, args, incomplete):
    # disable logging  so we don't spam
    # stdout with logging if something goes
    # kinda wrong
    logging.disable(60)
    try:
        all_certs = cert.get_all_certs()
        partition = args[-1]
        return sorted(
            [
                cert.name
                for cert in all_certs
                if cert.partition == partition and cert.name.startswith(incomplete)
            ]
        )
    except:
        return []


def need_configuration(need_account=True):
    """
    Decorator for functions that need the configuration files.
    """

    def config_decorator(func):
        def wrapper(*args, **kwargs):
            if not config.check_configfiles():
                click.secho(
                    "Could not find the configuration files in the specified folder.",
                    fg="red",
                    err=True,
                )
                sys.exit(1)

            if need_account:
                if not config.check_account_file():
                    click.secho(
                        "Could not find an account. You must register with the CA.",
                        fg="red",
                        err=True,
                    )
                    sys.exit(1)
            try:
                the_config = config.read_configfile()
            except (NoSectionError, NoOptionError, ValueError) as error:
                click.secho(
                    f"The configuration files was found, but was not complete: {error}",
                    fg="red",
                    err=True,
                )
                sys.exit(1)

            kwargs.update({"configuration": the_config})

            logging.config.fileConfig(
                config.LOG_CONFIG_FILE, disable_existing_loggers=False
            )
            func(*args, **kwargs)

        return wrapper

    return config_decorator


def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except RuntimeError:
            # Click abort inherits
            # from RuntimeError.
            raise
        except Exception as error:
            logger.exception("An unexpected error occured")
            click.secho(f"An unexpected error occured: {error}", fg="red", err=True)
            sys.exit(1)

    return wrapper


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config-dir",
    default=".",
    help="The config dir to use. Defaults to the current folder.",
    type=click.Path(),
)
def cli(config_dir):
    """ACME client for Big-IP"""
    try:
        os.chdir(os.path.abspath(config_dir))
    except OSError as error:
        if error.errno == 2:
            click.secho(
                f"Could not locate the specified configuration folder.",
                fg="red",
                err=True,
            )
            sys.exit(1)
        else:
            raise


@cli.command(name="new", help="Request a new certificate.")
@click.argument(  # type: ignore
    "partition", callback=utils.validate_bigip_name, autocompletion=partition_completer
)
@click.argument("csrname", callback=utils.validate_bigip_name)
@click.option("--dns", is_flag=True, help="Use DNS validation instead of HTTP.")
@need_configuration()
@handle_exceptions
def new_cert(partition, csrname, dns, configuration):
    """
    Fetches the specified CSR from the device
    and retrieves a certificate from the CA
    """
    logger.info(
        "User '%s' started issuance of cert '%s' in partition '%s'",
        getpass.getuser(),
        csrname,
        partition,
    )
    bigip = lb.LoadBalancer.create_from_config(configuration)

    if dns:
        try:
            dns_plugin = plugin.get_plugin(configuration)
        except plugin.NoPluginFoundError:
            logger.error(
                "No DNS plugin was found. "
                "Unable to get certificate by using DNS validation without plugin."
            )
            click.secho(
                "No DNS plugin was found. A DNS plugin is needed for DNS validation.",
                fg="red",
                err=True,
            )
            sys.exit(1)

        except plugin.InvalidConfigError as error:
            logger.exception("Failed to initialize plugin:")
            click.secho(
                f"Failed to initialize plugin. Error was: {error}", fg="red", err=True
            )
            sys.exit(1)

        chall_typ = cert.ValidationMethod.DNS01
    else:
        dns_plugin = None
        chall_typ = cert.ValidationMethod.HTTP01

    click.echo("Getting the CSR from the Big-IP...")

    try:
        with click_spinner.spinner():
            csr = bigip.get_csr(partition, csrname)
    except lb.PartitionNotFoundError:
        logger.info("The partition '%s' was not found on the device", partition)
        click.secho(
            "The specified partition does not seem to exist.", fg="yellow", err=True
        )
        sys.exit(2)

    except lb.AccessDeniedError:
        logger.error("The user was denied access by the load balancer")
        click.secho(
            "The user was denied access by the load balancer. "
            "Do the user have the Certificate Manager role in the specified partition?",
            fg="yellow",
            err=True,
        )
        sys.exit(2)

    except lb.NotFoundError:
        logger.info("The CSR '%s' was not found on the device", csrname)
        click.secho(
            "Could not find the csr on the big-ip. Check the spelling.",
            fg="yellow",
            err=True,
        )
        sys.exit(2)

    certobj = cert.Certificate.new(partition, csrname, csr, chall_typ)
    click.echo("Getting a new certificate from the CA. This may take a while...")
    acme_ca = ca.CertificateAuthority.create_from_config(configuration)

    try:
        with click_spinner.spinner():
            certificate = _get_new_cert(acme_ca, bigip, certobj, dns_plugin)
    except ca.GetCertificateFailedError as error:
        logger.error("Could not get a certificate from the CA: %s", error)
        if chall_typ == cert.ValidationMethod.HTTP01:
            click.secho(
                f"Is the iRule attached to the Virtual Server? "
                f"Could not get a certificate from the CA: {error}",
                fg="red",
                err=True,
            )
            sys.exit(1)

        else:
            click.secho(
                f"Could not get a certificate from the CA: {error}", fg="red", err=True
            )
            sys.exit(1)

    except plugin.PluginError as error:
        logger.exception("An error occured in %s:", dns_plugin.name)
        click.secho(
            f"An error occured while solving the challenge(s): {error}",
            fg="red",
            err=True,
        )
        sys.exit(1)

    certobj.cert = certificate
    bigip.upload_certificate(partition, csrname, certobj.cert)
    certobj.mark_as_installed()

    click.secho("Done.", fg="green")


@cli.command(name="renew", help="Renew existing certificates.")
@need_configuration()
@handle_exceptions
def renew(configuration):
    """Goes through all the issued certs and renews them if needed"""
    logger.info("Starting renewal process")
    renewals, certs_to_be_installed = cert.get_certs_that_need_action(configuration)

    if renewals or certs_to_be_installed:
        acme_ca = ca.CertificateAuthority.create_from_config(configuration)
        bigip = lb.LoadBalancer.create_from_config(configuration)

    dns_plugin = None
    for renewal in renewals:
        logger.info(
            "Renewing cert: '%s' from partition: '%s' using '%s'",
            renewal.name,
            renewal.partition,
            renewal.validation_method.value,
        )

        if renewal.validation_method == cert.ValidationMethod.DNS01 and not dns_plugin:
            try:
                dns_plugin = plugin.get_plugin(configuration)
            except plugin.PluginError:
                logger.exception(
                    "Could not load plugin to renew certificate '%s' in partition '%s':",
                    renewal.name,
                    renewal.partition,
                )
                continue

        try:
            certificate = _get_new_cert(acme_ca, bigip, renewal, dns_plugin)
        except (ca.GetCertificateFailedError, lb.LoadBalancerError, plugin.PluginError):
            logger.exception(
                "Could not renew certificate '%s' in partition '%s':",
                renewal.name,
                renewal.partition,
            )
            continue
        renewal.renew(certificate)

    for tbi_cert in certs_to_be_installed:
        logger.info(
            "Installing cert: '%s' in partition: '%s'",
            tbi_cert.name,
            tbi_cert.partition,
        )
        try:
            bigip.upload_certificate(tbi_cert.partition, tbi_cert.name, tbi_cert.cert)
        except lb.LoadBalancerError:
            logger.exception(
                "Could not install certificate '%s' in partition '%s':",
                tbi_cert.name,
                tbi_cert.partition,
            )
            continue
        tbi_cert.mark_as_installed()

    cert.delete_expired_backups()
    logger.info("Renewal process completed")


@cli.command(name="remove", help="Remove a certificate, so that it won't be renewed.")
@click.argument(  # type: ignore
    "partition", callback=utils.validate_bigip_name, autocompletion=partition_completer
)
@click.argument(  # type: ignore
    "csrname", callback=utils.validate_bigip_name, autocompletion=csrname_completer
)
@need_configuration()
@handle_exceptions
def remove(partition, csrname, configuration):
    """Removes a certificate so that it won't get renewed"""
    try:
        cert.Certificate.get(partition, csrname).delete()
    except cert.CertificateNotFoundError:
        click.secho("The specified certificate was not found.", fg="yellow", err=True)
        sys.exit(2)

    click.confirm(
        f"Are you sure you want to remove certificate '{csrname}' "
        f"in partition '{partition}'?",
        abort=True,
    )

    logger.info(
        "User '%s' removed cert '%s' in partition '%s'",
        getpass.getuser(),
        csrname,
        partition,
    )

    click.secho(f"Certificate removed.", fg="green")


@cli.command(name="revoke", help="Revoke a certificate.")
@click.argument(  # type: ignore
    "partition", callback=utils.validate_bigip_name, autocompletion=partition_completer
)
@click.argument(  # type: ignore
    "csrname", callback=utils.validate_bigip_name, autocompletion=csrname_completer
)
@need_configuration()
@handle_exceptions
def revoke(partition, csrname, configuration):
    """Revokes a certificate"""

    try:
        certificate = cert.Certificate.get(partition, csrname)
    except cert.CertificateNotFoundError:
        click.secho("The specified certificate was not found.", fg="yellow", err=True)
        sys.exit(2)

    click.echo(
        f"This will {click.style('REVOKE', bold=True)} the specified certificate. "
        f"It will no longer be usable."
    )
    click.echo()
    click.echo(
        f"You should {click.style('ONLY', bold=True)} do this if the private key "
        f"has been compromised. It is not necessary if the certificate is just "
        f"beeing retired."
    )
    click.echo()
    click.echo(
        f"Are you sure you want to revoke certificate '{csrname}' "
        f"in partition '{partition}'?"
    )
    click.echo()
    click.echo("Type REVOKE (all caps) if you are sure.")

    choice = input()
    if choice != "REVOKE":
        sys.exit("Aborted!")

    choice = ""
    while choice not in ("0", "1", "3", "4", "5"):
        click.echo("What is the reason you are revoking this cert?")
        click.echo("0) Unspecified")
        click.echo("1) Key compromise")
        click.echo("3) Affiliation changed")
        click.echo("4) Superseded")
        click.echo("5) Cessation of operation")
        choice = input().replace(")", "")
    reason = int(choice)

    acme_ca = ca.CertificateAuthority.create_from_config(configuration)
    acme_ca.revoke_certifciate(certificate.cert, reason)
    certificate.delete()
    logger.info(
        "User '%s' revoked cert '%s' in partition '%s'",
        getpass.getuser(),
        csrname,
        partition,
    )
    click.secho(f"Certificate revoked.", fg="green")


@cli.command(name="test", help="Test connectivity to the CA and the load balancer.")
@need_configuration(need_account=False)
@handle_exceptions
def test(configuration):
    """Tests the connections to the load balancer and the ca"""

    all_good = True

    try:
        lb.LoadBalancer.create_from_config(configuration)
    except lb.LoadBalancerError as error:
        click.secho(
            f"Could not connect to the load balancer: {error}", fg="red", err=True
        )
        logger.exception("Could not connect to the load balancer:")
        all_good = False
    else:
        click.secho("The connection to the load balancer was successfull.", fg="green")

    try:
        ca.CertificateAuthority.create_from_config(configuration)
    except ca.CAError as error:
        click.secho(f"Could not connect to the CA: {error}", fg="red", err=True)
        logger.exception("Could not connect to the CA:")
        all_good = False
    else:
        click.secho("The connection to the CA was successfull.", fg="green")

    if not all_good:
        sys.exit(1)


@cli.command(name="version", help="Show the version number and exit.")
def print_version():
    """Prints the version number and exits"""
    click.echo(version.__version__)


@cli.command(name="register", help="Generate an account key and register with the CA.")
@need_configuration(need_account=False)
@handle_exceptions
def register(configuration):
    """Genereates a account key, and registeres with the specified CA"""
    acme_ca = ca.CertificateAuthority.create_from_config(configuration)
    if acme_ca.key:
        click.secho(
            "Account config already exists - already registered?", fg="yellow", err=True
        )
        sys.exit(2)

    click.echo(
        "This will generate an account key and register it with the specified CA."
    )
    click.confirm("Do you want to continue?", abort=True)

    if "terms_of_service" in acme_ca.client.directory.meta:
        click.confirm(
            f"Do you agree with the terms of service, as described at "
            f"{acme_ca.client.directory.meta.terms_of_service}?",
            abort=True,
        )

    mail = click.prompt("What mail address do you want to register with the account?")

    click.confirm(f"You typed in '{mail}', is this correct?", abort=True)

    try:
        acme_ca.register(mail)
    except acme_errors.Error as error:
        logger.exception("Failed to register with the CA:")
        click.secho(f"The registration failed: {error}", fg="red", err=True)
        sys.exit(1)

    click.secho("Registration successful.", fg="green")


@cli.command(name="config", help="Generate a folder structure with config files.")
@click.option("-debug", is_flag=True)
def new_config(debug):
    """Creates the enviroment with configuration files and folders"""

    click.echo(
        "This will create the necessary folder structure, and configuration files "
        "in the specified configuration folder (default is the current folder)"
    )

    click.confirm("Do you want to continue?", abort=True)

    for folder in config.CONFIG_DIRS:
        try:
            os.makedirs(folder)
        except OSError as error:
            if error.errno == errno.EEXIST and os.path.isdir(folder):
                click.secho(
                    f"The folder '{folder}' already exists.", fg="yellow", err=True
                )
            else:
                raise

    if not os.path.exists(config.CONFIG_FILE):
        config.create_configfile()
    else:
        click.secho(
            "The config file already exists. Not touching it.", fg="yellow", err=True
        )

    if not os.path.exists(config.LOG_CONFIG_FILE):
        config.create_logconfigfile(debug)
    else:
        click.secho(
            "The logging config file already exists. Not touching it.",
            fg="yellow",
            err=True,
        )

        click.secho("Done! Adjust the configuration files as needed.", fg="green")


@cli.command(name="list", help="List all the certificates that will be renewed.")
@click.argument(  # type: ignore
    "partition",
    callback=utils.validate_bigip_name,
    autocompletion=partition_completer,
    required=False,
)
@need_configuration(need_account=False)
@handle_exceptions
def list_certs(partition, configuration):
    """Lists all the certs that are going to be renewed"""
    columns = ("Partition", "Name", "Validation method", "Status")
    all_certs = cert.get_all_certs()
    relevant_certs = []
    for certificate in all_certs:

        if partition and partition != certificate.partition:
            continue
        relevant_certs.append(
            (
                certificate.partition,
                certificate.name,
                certificate.validation_method.value,
                certificate.status.value,
            )
        )
    relevant_certs.sort()

    if relevant_certs:
        utils.print_table(columns, relevant_certs)
    else:
        click.secho("No certificates found.", fg="yellow", err=True)
        sys.exit(2)


def _get_new_cert(acme_ca, bigip, csr, dns_plugin):
    logger.debug("Getting the challenges from the CA")

    order = acme_ca.order_new_cert(csr.csr)
    challenges = acme_ca.get_challenges_to_solve_from_order(
        order, csr.validation_method
    )

    if csr.validation_method == cert.ValidationMethod.HTTP01:
        for challenge in challenges:
            bigip.send_challenge(
                challenge.identifier, challenge.challenge.path, challenge.validation
            )
    elif csr.validation_method == cert.ValidationMethod.DNS01:
        for challenge in challenges:
            record_name = challenge.challenge.validation_domain_name(
                challenge.identifier
            )
            dns_plugin.perform(challenge.identifier, record_name, challenge.validation)
        dns_plugin.finish_perform()
    else:
        raise ca.UnknownValidationType(
            f"Validation type '{csr.validation_method}' is not recognized"
        )

    acme_ca.answer_challenges(challenges)
    try:
        certificate = acme_ca.get_certificate_from_ca(order)
    finally:
        # cleanup
        if csr.validation_method == cert.ValidationMethod.HTTP01:
            for challenge in challenges:
                bigip.remove_challenge(challenge.identifier, challenge.challenge.path)
        elif csr.validation_method == cert.ValidationMethod.DNS01:
            for challenge in challenges:
                record_name = challenge.challenge.validation_domain_name(
                    challenge.identifier
                )
                dns_plugin.cleanup(
                    challenge.identifier, record_name, challenge.validation
                )
            dns_plugin.finish_cleanup()

    return certificate
