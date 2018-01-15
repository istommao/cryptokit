# coding: utf-8
"""test utils."""
from __future__ import unicode_literals

import datetime

from unittest import TestCase

from OpenSSL import crypto

from cryptokit.rsa import RSACrypto
from cryptokit.utils import load_pfx, generate_certificate, generate_pfx


class UtilTestCase(TestCase):
    """RSACrypto useage test."""

    def setUp(self):
        private_key = RSACrypto.generate_private_key(2048)

        RSACrypto.dump_private_key_pem(private_key)

        self.private_key = private_key
        self.public_key = private_key.public_key()

        validity = datetime.timedelta(days=365)
        self.not_valid_before = datetime.datetime.today()
        self.not_valid_after = self.not_valid_before + validity

        payload = {
            'common_name': 'CA',
            'country_name': 'CN',
            'email_address': 'codingcat@gmail.com',
            'org_name': '数字认证中心',
            'company_name': '编程猫科技',
            'state_or_province': '浙江省',
            'locality_name': '杭州市',
            'private_key': self.private_key,
            'public_key': self.public_key,
            'serial_number': 9219100179121295299
        }
        self.payload = payload

    def test_generate_certificate(self):
        """Test generate certificate."""

        cert = generate_certificate(
            self.not_valid_before, self.not_valid_after, **self.payload)

        self.assertEqual(cert.serial_number, self.payload['serial_number'])

    def test_generate_pfx(self):
        """Test generate pfx."""
        cert = generate_certificate(
            self.not_valid_before, self.not_valid_after, **self.payload)

        certificate = crypto.X509().from_cryptography(cert)
        private_key = crypto.PKey().from_cryptography_key(self.private_key)
        pfx = generate_pfx(
            certificate, self.payload['company_name'], private_key)

        pkcs12 = load_pfx(pfx)
        self.assertEqual(
            certificate.get_serial_number(),
            pkcs12.get_certificate().get_serial_number()
        )
