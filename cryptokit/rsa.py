# coding: utf-8
"""rsa crypto."""
from __future__ import unicode_literals

import warnings

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSACrypto(object):
    """RSACrypto."""

    ALGORITHM_DICT = {
        'sha1': hashes.SHA1(),
        'sha224': hashes.SHA224(),
        'sha256': hashes.SHA256(),
        'sha384': hashes.SHA384(),
        'sha512': hashes.SHA512()
    }

    @staticmethod
    def generate_private_key(key_size=2048, public_exponent=65537, backend=default_backend()):
        """Generate rsa private key."""
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=backend
        )
        return private_key

    @staticmethod
    def load_private_key_pem(pem_data, password=None):
        """Load private key pem."""
        backend = default_backend()
        return serialization.load_pem_private_key(pem_data.encode(), password, backend)

    @staticmethod
    def load_public_key_pem(pem_data):
        """Load public key pem."""
        backend = default_backend()
        return serialization.load_pem_public_key(pem_data.encode(), backend)

    @staticmethod
    def dump_private_key_pem(private_key):
        """Dump private key pem."""
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode()

    @staticmethod
    def dump_public_key_pem(public_key):
        """Dump public key pem."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()

    @classmethod
    def sign(cls, message, private_key, algorithm='sha1'):
        """signing."""
        if not isinstance(message, bytes):
            message = message.encode()

        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        return private_key.sign(message, cls._pss_padding(algorithm), algorithm)

    @classmethod
    def signing(cls, message, private_key, algorithm='sha1'):
        """signing() will deprecated in 0.1.0, use sign() please"""
        warnings.warn(
            'signing() will deprecated in 0.1.0, use sign() please', DeprecationWarning)
        return cls.sign(message, private_key, algorithm=algorithm)

    @classmethod
    def _oaep_padding(cls, algorithm):
        padding_data = padding.OAEP(
            mgf=padding.MGF1(algorithm=algorithm),
            algorithm=algorithm,
            label=None
        )
        return padding_data

    @classmethod
    def _pss_padding(cls, algorithm):
        padding_data = padding.PSS(
            mgf=padding.MGF1(algorithm),
            salt_length=padding.PSS.MAX_LENGTH
        )
        return padding_data

    @classmethod
    def verify(cls, message, signature, public_key, padding_mode='pss', algorithm='sha1'):
        """verify."""
        if not isinstance(message, bytes):
            message = message.encode()

        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        if padding_mode == 'pkcs1':
            padding_data = padding.PKCS1v15()
        else:
            padding_data = cls._pss_padding(algorithm)

        try:
            public_key.verify(signature, message,
                              padding_data, algorithm)
        except InvalidSignature:
            padd_verify = False
        else:
            padd_verify = True
        return padd_verify

    @classmethod
    def verification(cls, message, signature, public_key, algorithm='sha1'):
        """verification() will deprecated in 0.1.0, use verify() please"""
        warnings.warn(
            'verification() will deprecated in 0.1.0, use verify() please', DeprecationWarning)

        return cls.verify(message, signature, public_key, algorithm=algorithm)

    @classmethod
    def encrypt(cls, message, public_key, algorithm='sha1'):
        """Public key encrypt.

        :note: Valid paddings for encryption are OAEP and PKCS1v15.
        OAEP is the recommended choice for any new protocols or applications,
        PKCS1v15 should only be used to support legacy protocols.
        """
        if not isinstance(message, bytes):
            message = message.encode()

        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        return public_key.encrypt(message, cls._oaep_padding(algorithm))

    @classmethod
    def decrypt(cls, ciphertext, private_key, algorithm='sha1'):
        """Private key descrption.

        :note: Valid paddings for encryption are OAEP and PKCS1v15.
        OAEP is the recommended choice for any new protocols or applications,
        PKCS1v15 should only be used to support legacy protocols.
        """
        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        return private_key.decrypt(ciphertext, cls._oaep_padding(algorithm)).decode()
