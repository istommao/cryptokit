# coding: utf-8
"""test csr."""
from __future__ import unicode_literals

from unittest import TestCase

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_csr

from cryptokit import generate_csr
from cryptokit.rsa import RSACrypto


class CSRTestCase(TestCase):
    """csr usage test."""

    def test_success(self):
        """Test success."""
        private_key = RSACrypto.generate_private_key(2048)
        payload = {
            'country_name': 'US',
            'state_or_province': 'California',
            'locality_name': 'San Francisco',
            'org_name': 'My Company',
            'common_name': 'mysite.com',
            'dns_list': ['mysite.com', 'www.mysite.com', 'subdomain.mysite.com']

        }

        csr_data = generate_csr(private_key, encoding='pem', algorithm='sha256', **payload)
        csr = load_pem_x509_csr(csr_data, default_backend())

        rfc4514_string = 'C=US,ST=California,L=San Francisco,O=My Company,CN=mysite.com'
        self.assertEqual(rfc4514_string, csr.subject.rfc4514_string())
