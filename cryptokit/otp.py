# coding: utf-8
"""OTP TOTP"""
from __future__ import unicode_literals

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.hashes import SHA1


key = os.urandom(20)


def generate_htop(length=6, salt=0):
    hotp = HOTP(key, length, SHA1(), backend=default_backend())
    hotp_value = hotp.generate(salt)

    #  hotp.verify(hotp_value, 0)

    return hotp_value.decode()
