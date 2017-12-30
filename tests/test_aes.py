"""test aes."""

from unittest import TestCase

from cryptokit.aes import AESCrypto


class AESCryptoTestCase(TestCase):
    """AESCrypto useage test."""

    def test_success(self):
        message = "hello cryptokit"
        crypto = AESCrypto(
            'WDMG1e38igW53YuxkE0SsKUDeLbULAtL', 'm2VYHdx41zRgvg6f')
        data = crypto.encrypt(message)

        self.assertEqual(crypto.decrypt(data), message)
