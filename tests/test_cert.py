"""Tests for `cert.py`."""

import unittest
import OpenSSL
import bigacme.cert

def _get_testkey():
    """Returns the test key"""
    with open('./tests/testkey.pem', 'rb') as key_file:
        key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                             key_file.read())
    return key


def _generate_csr(cn, san):
    """Generates a csr for testing purposes"""
    key = _get_testkey()
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = cn
    if san:
        sn = ([OpenSSL.crypto.X509Extension("subjectAltName", False, san)])
        req.add_extensions(sn)
    req.set_pubkey(key)
    req.sign(key, "sha256")
    return OpenSSL.crypto.dump_certificate_request(
        OpenSSL.crypto.FILETYPE_PEM, req)

def _generate_certificate(not_before, not_after, filename):
    """Generates a certificate in a file for testing purposes"""
    key = _get_testkey()
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(357)
    cert.get_subject().CN = "test"
    cert.set_issuer(cert.get_subject())
    cert.gmtime_adj_notBefore(not_before)
    cert.gmtime_adj_notAfter(not_after)
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    f = open(filename, "w")
    f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                            cert))
    f.close()

class CertTestCase(unittest.TestCase):
    """Tests for the certificate functions"""

    def test_cert_about_to_expire(self):
        """Tests if a certificate about to expires is detected"""
        not_before = -10800
        not_after = 432000
        _generate_certificate(not_before, not_after, 'shortlived_cert.pem')
        self.assertTrue(bigacme.cert._check_if_cert_about_to_expire(
            'shortlived_cert.pem', 14))

    def test_cert_not_about_to_expire(self):
        """Tests if a certificate not about to expire is not detected"""
        not_before = -10800
        not_after = 15552000
        _generate_certificate(not_before, not_after, 'longlived_cert.pem')
        self.assertFalse(bigacme.cert._check_if_cert_about_to_expire(
            'longlived_cert.pem', 14))

    def test_get_cn_from_csr(self):
        """Does the function return the Common Name from the subject?"""
        cn = "example.org"
        csr = _generate_csr(cn, '')
        cn2 = bigacme.cert.get_hostnames_from_csr(csr)
        self.assertEqual([cn], cn2)

    def test_get_san_from_csr(self):
        """Does the function return SAN names?"""
        san_names = ["example.com", "example.org", "example.no"]
        sn = []
        for i in san_names:
            sn.append("DNS: %s" % i)
        sans = ", ".join(sn)

        csr = _generate_csr('test', sans)
        sans2 = bigacme.cert.get_hostnames_from_csr(csr)
        self.assertEqual(san_names, sans2)

    def test_new_cert_is_new(self):
        """Checks that a newly generated cert is marked as such"""
        not_before = 0
        not_after = 15552000
        _generate_certificate(not_before, not_after, 'new_cert.pem')
        self.assertFalse(bigacme.cert._check_if_cert_is_old_enough(
            'new_cert.pem', 14))

    def test_old_cert_is_old(self):
        """Checks that a old cert is marked as such"""
        not_before = -432000
        not_after = 15552000
        _generate_certificate(not_before, not_after, 'old_cert.pem')
        self.assertTrue(bigacme.cert._check_if_cert_is_old_enough(
            'old_cert.pem', 5))
