# coding: utf-8
"""aes crypto."""
from __future__ import unicode_literals

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESCrypto(object):
    """AESCrypto."""

    def __init__(self, aes_key, aes_iv):
        if not isinstance(aes_key, bytes):
            aes_key = aes_key.encode()

        if not isinstance(aes_iv, bytes):
            aes_iv = aes_iv.encode()

        self.aes_key = aes_key
        self.aes_iv = aes_iv

    def encrypt(self, data, mode='cbc'):
        """encrypt."""
        func_name = '{}_encrypt'.format(mode)
        func = getattr(self, func_name)
        return func(data)

    def decrypt(self, data, mode='cbc'):
        """decrypt."""
        func_name = '{}_decrypt'.format(mode)
        func = getattr(self, func_name)
        return func(data)

    def cbc_encrypt(self, data):
        """cbc_encrypt."""
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CBC(self.aes_iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = encryptor.update(self.pkcs7_padding(data))

        return padded_data

    def cbc_decrypt(self, data):
        """cbc_decrypt."""
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CBC(self.aes_iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        uppaded_data = self.pkcs7_unpadding(decryptor.update(data))

        uppaded_data = uppaded_data.decode()
        return uppaded_data

    @staticmethod
    def pkcs7_padding(data):
        """pkcs7_padding."""
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        """pkcs7_unpadding."""
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data
