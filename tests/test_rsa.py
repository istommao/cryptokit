"""test rsa."""

from unittest import TestCase

from cryptokit.rsa import RSACrypto


class RSACryptoTestCase(TestCase):
    """RSACrypto useage test."""

    def setUp(self):
        private_key = RSACrypto.generate_private_key(2048)

        RSACrypto.dump_private_key_pem(private_key)

        self.private_key = private_key
        self.public_key = private_key.public_key()

    def test_encryption_decryption(self):
        message = 'Hello RSACrypto'
        ciphertext = RSACrypto.encrypt(
            message, self.public_key, algorithm='sha1')

        plaintext = RSACrypto.decrypt(
            ciphertext, self.private_key, algorithm='sha1')

        self.assertEqual(plaintext, message)

    def test_signature_verification(self):
        message = 'Hello RSACrypto'
        signature = RSACrypto.signing(
            message, self.private_key, algorithm='sha1')

        success = RSACrypto.verification(
            message, signature, self.public_key, algorithm='sha1')

        self.assertTrue(success)

        signature = RSACrypto.sign(
            message, self.private_key, algorithm='sha1')

        success = RSACrypto.verify(
            message, signature, self.public_key, algorithm='sha1')

        self.assertTrue(success)
