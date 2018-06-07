# coding: utf-8
"""Elliptic Curve Signature Algorithms."""
from __future__ import unicode_literals


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class ECCrypto(object):

    ALGORITHM_DICT = {
        'sha1': hashes.SHA1(),
        'sha224': hashes.SHA224(),
        'sha256': hashes.SHA256(),
        'sha384': hashes.SHA384(),
        'sha512': hashes.SHA512()
    }

    def __init__(self, private_key=None):
        self.private_key = private_key

    def generate_private_key(self):
        private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        return private_key

    def sign(self, private_key, data, algorithm='sha256'):
        algorithm_obj = self.ALGORITHM_DICT.get(algorithm)

        signature = private_key.sign(
            data,
            ec.ECDSA(algorithm_obj)
        )
        return signature
