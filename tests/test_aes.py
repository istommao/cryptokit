# coding: utf-8
"""test aes."""
from __future__ import unicode_literals


from unittest import TestCase

from cryptokit.aes import AESCrypto
from cryptokit.exception import AesException


class AESCryptoTestCase(TestCase):
    """AESCrypto useage test."""

    def test_success(self):
        """Test success."""
        message = "hello cryptokit"
        crypto = AESCrypto(
            'WDMG1e38igW53YuxkE0SsKUDeLbULAtL', 'm2VYHdx41zRgvg6f')
        data = crypto.encrypt(message)

        self.assertEqual(crypto.decrypt(data), message)

    def test_failure(self):
        """Test failure."""
        crypto = AESCrypto(
            'WDMG1e38igW53YuxkE0SsKUDeLbULAtL', 'm2VYHdx41zRgvg6f')

        with self.assertRaises(AesException):
            crypto.decrypt('234234'.encode())

    def test_aes_ctr(self):
        """Test aes ctr success."""
        message = "hello cryptokit"
        crypto = AESCrypto(
            'WDMG1e38igW53YuxkE0SsKUDeLbULAtL', 'm2VYHdx41zRgvg6f')
        data = crypto.encrypt(message, mode='ctr')

        self.assertEqual(crypto.decrypt(data, mode='ctr'), message)
