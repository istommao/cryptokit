# coding: utf-8
"""x25519"""
from __future__ import unicode_literals

import base64

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519 as raw_x25519

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl.backend import backend

from . import _ge25519, _fe25519


def get_prviate_key_from_ed25519_hex(ed25519_hex_str: str):
    if not backend.x25519_supported():
        raise UnsupportedAlgorithm(
            "X25519 is not supported by this version of OpenSSL.",
            _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
        )

    data = bytes.fromhex(ed25519_hex_str)

    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(data)
    h = bytearray(hasher.finalize())
    # curve25519 clamping
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64

    return backend.x25519_load_private_bytes(h[0:32])


def get_public_key_from_ed25519_hex(ed25519_hex_str: str):
    if not backend.x25519_supported():
        raise UnsupportedAlgorithm(
            "X25519 is not supported by this version of OpenSSL.",
            _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
        )

    public_bytes = bytes.fromhex(ed25519_hex_str)
    # This is libsodium's crypto_sign_ed25519_pk_to_curve25519 translated into
    # the Pyton module ge25519.
    if _ge25519.ge25519.has_small_order(public_bytes) != 0:
        raise ValueError("Doesn't have small order")

    # frombytes in libsodium appears to be the same as
    # frombytes_negate_vartime; as ge25519 only implements the from_bytes
    # version, we have to do the root check manually.
    A = _ge25519.ge25519_p3.from_bytes(public_bytes)
    if A.root_check:
        raise ValueError("Root check failed")

    if not A.is_on_main_subgroup():
        raise ValueError("It's on the main subgroup")

    one_minus_y = _fe25519.fe25519.one() - A.Y
    x = A.Y + _fe25519.fe25519.one()
    x = x * one_minus_y.invert()

    x25519_public_bytes = bytes(x.to_bytes())
    return backend.x25519_load_public_bytes(x25519_public_bytes)


def get_share_secret(private_key, target_public_key, out_format="hex"):
    bytes_secret = private_key.exchange(target_public_key)
    if out_format == "hex":
        return bytes_secret.hex()
    elif bytes_secret == "base64":
        return base64.b64encode(bytes_secret).decode('utf-8')
    else:
        return bytes_secret


def get_share_secret_from_hex(private_key_hex, target_public_key_hex, out_format="hex"):
    private_key = raw_x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    target_public_key = raw_x25519.X25519PublicKey.from_private_bytes(bytes.fromhex(target_public_key_hex))

    bytes_secret = private_key.exchange(target_public_key)
    if out_format == "hex":
        return bytes_secret.hex()
    elif bytes_secret == "base64":
        return base64.b64encode(bytes_secret).decode('utf-8')
    else:
        return bytes_secret


def get_share_secret_from_base64(private_key_b64, target_public_key_b64, out_format="hex"):
    private_key = raw_x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(private_key_hex))
    target_public_key = raw_x25519.X25519PublicKey.from_private_bytes(base64.b64decode(target_public_key_hex))

    bytes_secret = private_key.exchange(target_public_key)
    if out_format == "hex":
        return bytes_secret.hex()
    elif bytes_secret == "base64":
        return base64.b64encode(bytes_secret).decode('utf-8')
    else:
        return bytes_secret
