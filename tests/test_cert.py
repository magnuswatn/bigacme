"""Tests for `cert.py`."""

import os
import unittest
import tempfile
from collections import namedtuple

import OpenSSL
import bigacme.cert

def _get_testkey():
    """Returns the test key"""
    with open('./testkey.pem', 'r') as key_file:
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

def _write_file(filename, content):
    with open(filename, 'w') as open_file:
        open_file.write(content)

def _read_file(filename):
    with open(filename, 'r') as open_file:
        return open_file.read()

class CertTestCase(unittest.TestCase):
    """Tests for the certificate functions"""

    @classmethod
    def setUpClass(cls):
        temp_dir = tempfile.mkdtemp()
        os.chdir(temp_dir)
        folders = ["config", "cert", "csr", "cert/backup", "cert/to_be_installed"]
        for folder in folders:
            os.makedirs(folder)
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        with open('./testkey.pem', 'w') as key_file:
            key_file.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    def test_cert_about_to_expire(self):
        """Tests if a certificate about to expires is detected"""
        _generate_certificate(-10800, 432000, 'shortlived_cert.pem')
        self.assertTrue(bigacme.cert._check_if_cert_about_to_expire(
            'shortlived_cert.pem', 14))

    def test_cert_not_about_to_expire(self):
        """Tests if a certificate not about to expire is not detected"""
        _generate_certificate(-10800, 15552000, 'longlived_cert.pem')
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
        _generate_certificate(0, 15552000, 'new_cert.pem')
        self.assertFalse(bigacme.cert._check_if_cert_is_old_enough(
            'new_cert.pem', 14))

    def test_old_cert_is_old(self):
        """Checks that a old cert is marked as such"""
        _generate_certificate(-432000, 15552000, 'old_cert.pem')
        self.assertTrue(bigacme.cert._check_if_cert_is_old_enough(
            'old_cert.pem', 5))

    def test_get_name_from_filename(self):
        """Checks that get_name_from_filename works"""
        partition = "partition"
        name = "test_get_name_from_filename"
        filename = "%s_%s.cer" % (partition, name)
        partition2, name2 = bigacme.cert.get_name_from_filename(filename)
        self.assertEqual(partition, partition2)
        self.assertEqual(name, name2)

    def test_load_csr_from_disk(self):
        """Checks that load_csr_from_disk works"""
        content = 'test_load_csr_from_disk'
        with open('./csr/partition_alias.csr', 'w') as open_file:
            open_file.write(content)
        content2 = bigacme.cert.load_csr_from_disk('partition', 'alias')
        self.assertEqual(content, content2)

    def test_load_renewed_cert_from_disk(self):
        content = 'test_load_renewed_cert_from_disk'
        with open('./cert/to_be_installed/partition_alias.cer', 'w') as open_file:
            open_file.write(content)
        content2 = bigacme.cert.load_renewed_cert_from_disk('partition', 'alias')
        self.assertEqual(content, content2)

    def test_move_renewed_cert(self):
        _write_file('./cert/to_be_installed/test_move_renewed_cert', 'test_move_renewed_cert')
        bigacme.cert.move_renewed_cert('test_move_renewed_cert')
        self.assertTrue(os.path.exists('./cert/test_move_renewed_cert'))
        self.assertFalse(os.path.exists('./cert/to_be_installed/test_move_renewed_cert'))

    def test_move_cert_to_backup(self):
        _write_file('./cert/test_move_cert_to_backup', 'test_move_cert_to_backup')
        bigacme.cert.move_cert_to_backup('test_move_cert_to_backup')

        self.assertFalse(os.path.exists('./cert/test_move_cert_to_backup'))
        self.assertTrue(os.path.exists('./cert/backup/test_move_cert_to_backup'))

    def test_save_renewed_cert_to_disk(self):
        partition = "partition"
        name = "test_save_renewed_cert_to_disk"
        content = 'test_save_renewed_cert_to_disk'
        filename = "%s_%s.cer" % (partition, name)
        bigacme.cert.save_renewed_cert_to_disk(partition, name, content)
        content2 = _read_file('./cert/to_be_installed/%s' % filename)
        self.assertEqual(content, content2)

    def test_save_cert_to_disk(self):
        partition = "partition"
        name = "test_save_cert_to_disk"
        content = 'test_save_cert_to_disk'
        filename = "%s_%s.cer" % (partition, name)
        bigacme.cert.save_cert_to_disk(partition, name, content)
        content2 = _read_file('./cert/%s' % filename)
        self.assertEqual(content, content2)

    def test_save_csr_to_disk(self):
        partition = "partition"
        name = "test_save_csr_to_disk"
        content = 'test_save_csr_to_disk'
        filename = "%s_%s.csr" % (partition, name)
        bigacme.cert.save_csr_to_disk(partition, name, content)
        content2 = _read_file('./csr/%s' % filename)
        self.assertEqual(content, content2)

    def test_load_associated_csr(self):
        content = 'test_load_associated_csrr'
        _write_file('./csr/partition_alias.csr', content)
        content2 = bigacme.cert.load_associated_csr('partition_alias.cer')
        self.assertEqual(content, content2)

    def test_load_cert_from_disk_to_be_installed(self):
        content = 'test_load_cert_from_disk_to_be_installed'
        _write_file('./cert/to_be_installed/partition_test_load_cert_from_disk_to_be_installed.cer',
                    content)
        content2 = bigacme.cert.load_cert_from_disk('partition',
                                                    'test_load_cert_from_disk_to_be_installed')
        self.assertEqual(content, content2)

    def test_load_cert_from_disk(self):
        content = 'test_load_cert_from_disk'
        _write_file('./cert/partition_test_load_cert_from_disk.cer', content)
        content2 = bigacme.cert.load_cert_from_disk('partition', 'test_load_cert_from_disk')
        self.assertEqual(content, content2)

    def test_load_cert_from_disk_not_exists(self):
        self.assertRaises(bigacme.cert.CertificateNotFoundError,
                          bigacme.cert.load_cert_from_disk, 'partition',
                          'test_load_cert_from_disk_not_exists')

    def test_delete_expired_backups(self):
        _generate_certificate(-15552000, -10800, './cert/backup/expired.pem')
        _generate_certificate(-10800, 15552000, './cert/backup/not_expired.pem')
        bigacme.cert.delete_expired_backups()
        self.assertFalse(os.path.exists('./cert/backup/expired.pem'))
        self.assertTrue(os.path.exists('./cert/backup/not_expired.pem'))

    def test_check_for_renewals(self):
        _generate_certificate(-10800, 432000, './cert/shortlived_cert.pem')
        _generate_certificate(-10800, 15552000, './cert/longlived_cert.pem')
        configtp = namedtuple("Config", ["cm_renewal_days"])
        config = configtp(cm_renewal_days=12)
        renewals = bigacme.cert.check_for_renewals(config)
        self.assertTrue('shortlived_cert.pem' in renewals)
        self.assertFalse('longlived_cert.pem' in renewals)

    def test_get_certificate_to_be_installed(self):
        _generate_certificate(0, 15552000, './cert/to_be_installed/new_cert.pem')
        _generate_certificate(-432000, 15552000, './cert/to_be_installed/old_cert.pem')
        configtp = namedtuple("Config", ["cm_delayed_days"])
        config = configtp(cm_delayed_days=5)
        renewals = bigacme.cert.get_certificate_to_be_installed(config)
        self.assertTrue('old_cert.pem' in renewals)
        self.assertFalse('new_cert.pem' in renewals)

    def test_remove_cert(self):
        _write_file('./csr/partition_test_remove_cert.csr', 'test_remove_cert')
        _write_file('./cert/partition_test_remove_cert.cer', 'test_remove_cert')
        bigacme.cert.remove_cert('partition', 'test_remove_cert')
        self.assertFalse(os.path.exists('./csr/partition_test_remove_cert.csr'))
        self.assertFalse(os.path.exists('./cert/partition_test_remove_cert.cer'))

    def test_remove_cert_tbi(self):
        _write_file('./csr/partition_test_remove_cert_tbi.csr', 'test_remove_cert_tbi')
        _write_file('./cert/to_be_installed/partition_test_remove_cert_tbi.cer',
                    'test_remove_cert_tbi')
        bigacme.cert.remove_cert('partition', 'test_remove_cert_tbi')
        self.assertFalse(os.path.exists('./csr/test_remove_cert_tbi.csr'))
        self.assertFalse(os.path.exists('./cert/to_be_installed/test_remove_cert_tbi.cer'))

    def test_remove_cert_both(self):
        _write_file('./csr/partition_test_remove_cert_both.csr', 'test_remove_cert_both')
        _write_file('./cert/partition_test_remove_cert_both.cer', 'test_remove_cert_both')
        _write_file('./cert/to_be_installed/partition_test_remove_cert_both.cer',
                    'test_remove_cert_both')
        bigacme.cert.remove_cert('partition', 'test_remove_cert_both')
        self.assertFalse(os.path.exists('./csr/test_remove_cert_both.csr'))
        self.assertFalse(os.path.exists('./cert/test_remove_cert_both.cer'))
        self.assertFalse(os.path.exists('./cert/to_be_installed/test_remove_cert_both.cer'))

    def test_remove_cert_no_csr(self):
        _write_file('./cert/partition_test_remove_cert_no_csr.cer', 'test_remove_cert_no_csr')
        self.assertRaises(bigacme.cert.CertificateNotFoundError,
                          bigacme.cert.remove_cert, 'partition', 'test_remove_cert_both')

    def test_remove_cert_no_cert(self):
        _write_file('./csr/partition_test_remove_cert_no_cert.csr', 'test_remove_cert_no_cert')
        self.assertRaises(bigacme.cert.CertificateNotFoundError,
                          bigacme.cert.remove_cert, 'partition', 'test_remove_cert_both')
