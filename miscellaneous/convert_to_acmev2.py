#!/usr/bin/env python3
"""Script to convert bigacme configuration files from 0.6 to 2019.x.x"""
import os
import sys
import json
import uuid
import configparser

from pathlib import Path
from collections import namedtuple
from distutils.version import LooseVersion  # pylint: disable=E0611, E0401

import attr
import josepy
from acme import messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from bigacme import version
from bigacme import ca as bigacme_ca
from bigacme import config as bigacme_config


class OnlyExistingRegistration(messages.ResourceBody):
    """
    Registration Resource Body with the onlyReturnExisting field set to True
    """

    only_return_existing = josepy.Field("onlyReturnExisting", True)


@attr.s
class ConfigurationMigrator:

    config = attr.ib(default=None)
    acme_ca = attr.ib(default=None)
    old_account_key = attr.ib(default=None)

    def convert_configuration(self):
        """Converts a bigacme configuration file from 0.6 to 2019.x.x"""
        config_file = bigacme_config.CONFIG_FILE
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

        include_chain_option = self.config.getboolean("Common", "include chain")

        if not include_chain_option:
            print("WARNING: include chain option set to False")
            print("WARNING: this will be forced on from now on")
        self.config.remove_option("Common", "include chain")

        self.old_account_key = self.config.get("Common", "account key")
        if self.old_account_key[-7:] == "key.pem":
            account_key = f"{self.old_account_key[:-7]}account.json"
        else:
            # Non-standard account key name,
            # let's just add .json to it.
            account_key = f"{self.old_account_key}.json"

        self.config.remove_option("Common", "account key")
        self.config.set("Common", "account config", account_key)

        org_directory_url = self.config.get("Certificate Authority", "directory url")
        new_directory_url = self._get_updated_directory_url(org_directory_url)

        if new_directory_url:
            self.config.set("Certificate Authority", "Directory URL", new_directory_url)
            print(
                f"Changed directory url from '{org_directory_url}' to '{new_directory_url}'"
            )
        else:
            print("WARN! Unknown directory url, must be switched to v2 manually.")

    def convert_account(self):
        """Converts an account key to an account.json file"""

        config = self.get_new_config()

        self.acme_ca = bigacme_ca.CertificateAuthority.create_from_config(config)

        # Read the old style account key
        old_key_file = Path(self.old_account_key)
        private_key = serialization.load_pem_private_key(
            old_key_file.read_bytes(), password=None, backend=default_backend()
        )
        self.acme_ca.key = josepy.JWKRSA(key=private_key)
        self.acme_ca.client.net.key = self.acme_ca.key

        regr_msg = OnlyExistingRegistration()
        try:
            regr_response = self.acme_ca.client._post(
                self.acme_ca.client.directory["newAccount"], regr_msg
            )
        except messages.Error as error:
            print("WARN: Your CA does not recognize your account.")
            print("WARN: Can't convert the accound configuration.")
            print("WARN: You must register again manually.")
            print("Error msg:")
            print(error)
            return

        regr_uri = regr_response.headers.get("Location")
        print(f"Retrieved account ID from the CA: '{regr_uri}'")
        self.acme_ca.kid = regr_uri

    def convert_stored_certs(self):
        """Converts an stored certs to 2019 version format"""
        for path in Path("cert").iterdir():
            if not path.is_file():
                continue

            print(f"Updating {path}")
            loaded = json.loads(path.read_text())

            # just rename
            loaded["csr"] = loaded.pop("_csr")

            # add chain to cert
            cert = loaded.pop("_cert")
            chain = loaded.pop("chain")
            for chain_cert in chain:
                cert += chain_cert

            loaded["cert"] = cert

            try:
                path.write_text(json.dumps(loaded, indent=4, sort_keys=True))
            except IOError as error:
                if error.errno == 13:
                    # It may be owned by another user,
                    # try to recreate it.
                    temp_path = Path(str(uuid.uuid1()))
                    path.rename(temp_path)
                    path.write_text(json.dumps(loaded, indent=4, sort_keys=True))
                    temp_path.unlink()
                else:
                    raise

    def get_new_config(self):
        configtp = namedtuple("Config", ["ca", "ca_proxy", "cm_account"])
        if self.config.getboolean("Certificate Authority", "use proxy"):
            ca_proxy = self.config.get("Certificate Authority", "proxy")
        else:
            ca_proxy = False

        return configtp(
            ca=self.config.get("Certificate Authority", "directory url"),
            ca_proxy=ca_proxy,
            cm_account=self.config.get("Common", "account config"),
        )

    @staticmethod
    def _get_updated_directory_url(old_directory_url):
        if old_directory_url == "https://acme-v01.api.letsencrypt.org/directory":
            return "https://acme-v02.api.letsencrypt.org/directory"
        elif old_directory_url == "https://acme-staging.api.letsencrypt.org/directory":
            return "https://acme-staging-v02.api.letsencrypt.org/directory"
        return None

    def save_changes(self):

        print("Saving updated configuration file")
        # As the config file contains password,
        # we must be careful with permissions.
        bigacme_config.CONFIG_FILE.touch(mode=0o660)

        with bigacme_config.CONFIG_FILE.open(mode="w") as open_config_file:
            self.config.write(open_config_file)

        print("Saving account config")
        self.acme_ca._save_account()

        print(f"Deleting old account key ({self.old_account_key})")
        Path(self.old_account_key).unlink()


def main():
    if not LooseVersion(version.__version__) >= LooseVersion("2019.0.0"):
        print("You need a 2019 version of bigacme for this script")
        sys.exit(1)

    if not bigacme_config.CONFIG_FILE.exists():
        print("This script must be run from the configuration folder. Exiting.")
        sys.exit(1)

    config_migrator = ConfigurationMigrator()

    config_migrator.convert_configuration()
    config_migrator.convert_account()
    config_migrator.convert_stored_certs()
    config_migrator.save_changes()

    print("Done")


if __name__ == "__main__":
    main()
