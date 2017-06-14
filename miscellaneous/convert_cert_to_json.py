#!/usr/bin/python2.7
"""Script to convert the old config structure with PEM certs to the new one with JSON files"""
import os
import sys

import bigacme.cert


def get_name_from_filename(filename):
    """Gets the partition and name from a filename"""
    partition = filename.split('_', 1)[0]
    name = filename.split('_', 1)[1][:-4]
    return partition, name

def load_associated_csr(certname):
    """Loads the csr associated with the specified cert file"""
    name = '%scsr' % certname[:-3]
    csr_file = './csr/%s' % name
    with open(csr_file, 'r') as open_file:
        csr = open_file.read()
    return csr_file, csr

def split_cert_and_chain(pem_chain):
    cert = chain = ''
    lines = pem_chain.split('\n')
    x = 0
    while lines[x-1] != '-----END CERTIFICATE-----' and x < len(lines):
        cert += (lines[x] + '\n')
        x += 1
    while x < len(lines):
        chain += (lines[x] + '\n')
        x += 1
    return cert, chain


def main():
    if not os.path.isdir('./cert/backup'):
        print 'This script must be run from the configuration folder. Exiting.'
        sys.exit(1)

    for filename in os.listdir('./cert'):
        fullpath = './cert/%s' % filename
        if not os.path.isfile(fullpath):
            continue

        partition, name = get_name_from_filename(filename)
        cert = bigacme.cert.Certificate(partition, name)

        with open(fullpath, 'r') as open_file:
            pem_cert, pem_chain = split_cert_and_chain(open_file.read())
        try:
            cert.cert, cert.chain = pem_cert, pem_chain
        except ValueError as error:
            if error.message == 'Unable to load certificate':
                print 'WARN: Could not load %s as a certificate' % filename
                continue
            else:
                raise
        csr_file, cert.csr = load_associated_csr(filename)
        cert.mark_as_installed()
        os.remove(fullpath)
        os.remove(csr_file)

    for filename in os.listdir('./cert/to_be_installed'):
        fullpath = './cert/to_be_installed/%s' % filename
        if not os.path.isfile(fullpath):
            continue

        partition, name = get_name_from_filename(filename)
        cert = bigacme.cert.Certificate(partition, name)
        with open(fullpath, 'r') as open_file:
            pem_cert, pem_chain = split_cert_and_chain(open_file.read())
        try:
            cert.cert, cert.chain = pem_cert, pem_chain
        except ValueError as error:
            if error.message == 'Unable to load certificate':
                print 'WARN: Could not load %s as a certificate' % filename
                continue
            else:
                raise
        csr_file, cert.csr = load_associated_csr(filename)
        cert.status = 'To be installed'
        cert.save()
        os.remove(fullpath)
        os.remove(csr_file)
    os.rmdir('./cert/to_be_installed')

    print 'Done. The csr folder can be deleted now'

if __name__ == '__main__':
    main()
