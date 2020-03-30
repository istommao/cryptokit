# coding: utf-8
"""test utils."""
from __future__ import unicode_literals

import datetime

from unittest import TestCase

from cryptokit.rsa import RSACrypto
from cryptokit.utils import (load_pfx, generate_certificate, generate_pfx,
                             get_pubkey_from_pfx)


class UtilTestCase(TestCase):
    """RSACrypto usage test."""

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

        pfx = generate_pfx(
            cert, self.payload['company_name'], self.private_key)

        pkcs12 = load_pfx(pfx)
        self.assertEqual(
            cert.serial_number,
            pkcs12.get_certificate().get_serial_number()
        )

    def test_get_pubkey_from_pfx(self):
        """Test get_pubkey_from_pfx."""
        cert = generate_certificate(
            self.not_valid_before, self.not_valid_after, **self.payload)

        pfx_file = generate_pfx(
            cert, self.payload['company_name'], self.private_key)

        pubkey = get_pubkey_from_pfx(pfx_file, password=None)

        self.assertEqual(cert.public_key().public_numbers(),
                         pubkey.public_numbers())
