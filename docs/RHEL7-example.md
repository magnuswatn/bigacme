# Example installation on RHEL 7

This is an example of how you can install bigacme on RHEL 7, and use the setup with several Big-IPs.

## Prerequisites

Python in RHEL 7 does not do certificate validation by default. This is bad, and must be changed. It is configured in the file */etc/python/cert-verification.cfg*.

Change from:

```
[https]
verify=platform_default
```
to:
```
[https]
verify=enable
```

After this, the CA that issued the certificates for the Big-IP must be trusted (add it to /etc/pki/ca-trust/source/anchors and run update-ca-trust).

Then install some extra needed packages:

`# yum install python-virtualenv libffi-devel gcc git openssl-devel`

As RHEL 7 does not have Python 3.6 by default, you'll also need to install it. It can be installed from EPEL, RHSCL or manually.

Add a user for bigacme:

`# useradd bigacme`

Create configuration folders:

```
# mkdir -p /opt/bigacme/venvs /opt/bigacme/configs
# chown bigacme:bigacme /opt/bigacme -R
```

Users that should have the privilege to issue certificate should be added to the bigacme group. The rest of this guide should be done as the bigacme user.

## Installation of virtualenv

Virtualenv is an easy way to run several individual python environments on the same server. It makes it possible to run to versions of bigacme on the same server (e.g. so that we can upgrade test before production).

Create a virtual python environment and activate it:

```
$ python36 -m venv /opt/bigacme/venvs/1
$ source /opt/bigacme/venvs/1/bin/activate
```

Upgrade pip and setuptools:

```
$ pip install --upgrade pip
$ pip install --upgrade setuptools
```

We can now install bigacme. Install the smoking fresh version from Github:

`$ pip install git+https://github.com/magnuswatn/bigacme.git`

## Configuration of bigacme

Now we are ready to do the configuration for bigacme. Repeat these steps for every Big-IP you have (e.g. dev, test, producation). Here we are configuring it for a Big-IP we'll call "bigip-test".

Create a config folder:

```
$ mkdir /opt/bigacme/configs/bigip-test
$ cd /opt/bigacme/configs/bigip-test
$ bigacme config
```

Change the config in config/config.ini according to your needs (see the "Configure bigacme" section in the installation doc).

Register with the CA:

`$ bigacme register`

To make it easier to activate the virtualenv we can make an alias. Add the following to /etc/profile.d/bigacme.sh

```bash
alias bigip-test='if [ "$(type -t deactivate)" ]; then deactivate; fi; source /opt/bigacme/venvs/1/bin/activate; cd /opt/bigacme/configs/bigip-test/; eval "$(_BIGACME_COMPLETE=source bigacme)"'
```

Now you can run "bigip-test" and it will deactivate the current virtualenv (if in an virtualenv), activate the "1" virtualenv, and change directory to the configuration folder for the test box.

Then we need to add a cron job. Create this script as bigip-test-cron.sh in bigacme's home folder (with execute permission):

```bash
#/bin/bash
source /etc/profile.d/bigacme.sh
bigip-test
bigacme renew
```

Then add the following to the crontab for the bigacme user:

```0 12 * * * /home/bigacme/bigip-test-cron.sh```

This will check for renewals every day (adjust as needed).

## Issuing certificates

Add the iRule to the relevant virtual server and create a csr on the Big-IP. Here we assume the csr is called "ImportantApp.no_LetsEncrypt" and it's in the partition "ImportantApp".

Log into the server, run:

```
$ testbigip
$ bigacme new ImportantApp ImportantApp.no_LetsEncrypt
```

This will issue a certificate. And it will be renewed according to the config and the cron job schedule.

## Upgrading Bigacme

If you want to upgrade Bigacme, you can just create a new virtual environemt, install bigacme, and then change the path in the /etc/profile.d/bigacme.sh. You can take one Big-IP instance at the time (start with dev, then test, then production), and when you have moved every instance over to the new version, you can delete the first virtual environment.
