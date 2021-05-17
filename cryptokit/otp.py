# coding: utf-8
"""OTP TOTP"""
from __future__ import unicode_literals

import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.hashes import SHA1


key = os.urandom(20)


def generate_htop(length=6, salt=0):
    hotp = HOTP(key, length, SHA1(), backend=default_backend())
    hotp_value = hotp.generate(salt)

    return hotp_value.decode()


def is_valid_totp(totp_value: str):
    key = os.urandom(20)
    totp = TOTP(key, 6, SHA1(), 30)

    time_value = time.time()

    try:
        totp.verify(totp_value.encode('utf-8'), time_value)
    except:
        return False
    else:
        return True


def get_provisioning_uri(key: str):
    totp = TOTP(key.encode('utf-8'), 6, SHA1(), 30)

    issuer_name = 'crypokit Inc'
    account_name = 'crypokit@email.com'

    totp_uri = totp.get_provisioning_uri(account_name, issuer_name)
    return totp_uri
