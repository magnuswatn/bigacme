bigacme
=====
[![Build Status](https://travis-ci.org/magnuswatn/bigacme.svg?branch=master)](https://travis-ci.org/magnuswatn/bigacme)
[![codecov](https://codecov.io/gh/magnuswatn/bigacme/branch/master/graph/badge.svg)](https://codecov.io/gh/magnuswatn/bigacme)

An ACME client for F5 Big-IP.

It can be used to get certificates from a ACME compatible CA, and auto-renew them before they expire. This can reduce the administrative burden of SSL.

<p align="center">
    <img src="https://static.watn.no/bigacme.svg">
</p>

## Prerequisites
* F5 Big-IP, version 11 or higher
* A server with access to both the Big-IP and the CA

## How it works
You manually create a CSR on the Big-IP and then tells bigacme to turn it into a certificate. Bigacme does so by configuring the Big-IP to answer the challenges from the CA. When it's time to renew the certficiate, bigacme repeats the process.

See more detailed information in the docs folder.
