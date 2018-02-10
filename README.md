bigacme
=====
[![Build Status](https://travis-ci.org/magnuswatn/bigacme.svg?branch=master)](https://travis-ci.org/magnuswatn/bigacme)
[![codecov](https://codecov.io/gh/magnuswatn/bigacme/branch/master/graph/badge.svg)](https://codecov.io/gh/magnuswatn/bigacme)

An ACME client for F5 Big-IP. It runs on a seperate computer, and talks to the Big-IP via iControl.

It can be used to get certificates from a ACME compatible CA, and auto-renew them before they expire. This can reduse the administrative burden of SSL.

It's a work in progress...

## Prerequisites
* F5 Big-IP, version 11 or higher
* A server with access to both the Big-IP and the CA

## How it works
You manually create a CSR on the Big-IP and then tells bigacme to turn it into a certiticate. Bigacme retrieves it, get challenges for the domains from the CA, configures the Big-IP to answer those challenges, and then gets the certificate from the CA and installs it om the Big-IP. The process will happen again when it is time to renew the certificate. The private keys are generated on the Big-IP and never leaves it.

See more detailed information in the docs folder.
