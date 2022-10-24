# coding: utf-8
"""Ed25519"""
from __future__ import unicode_literals

import base64

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as raw_ed25519

from .exception import ED25519Exception
from . import x25519


def generate_ed25519_key_pair(format_type=None):
    private_key_obj = raw_ed25519.Ed25519PrivateKey.generate()
    pubkey_obj = private_key_obj.public_key()

    if not format_type:
        return private_key_obj, pubkey_obj

    private_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = pubkey_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if format_type == "hex":
        return private_bytes.hex(), public_bytes.hex()
    elif format_type == "base64":
        private_key = base64.b64encode(private_bytes).decode()
        pubkey = base64.b64encode(public_bytes).decode()
        return private_key, pubkey
    elif format_type == "bytes":
        return private_bytes, public_bytes
    else:
        raise ED25519Exception("Invalid format type")


def load_ed25519_private_key_from_hex(private_key_hex: str):
    return raw_ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))


def load_ed25519_pubkey_from_hex(pubkey_hex: str):
    return raw_ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))


def ed25519_sign(private_key_hex: str, plain_text: str):
    private_key = load_ed25519_private_key_from_hex(private_key_hex)
    signature = private_key.sign(plain_text.encode('utf-8'))

    return signature


def ed25519_verify(pub_key_hex: str, signature: bytes, plain_text: str):

    pubkey = load_ed25519_pubkey_from_hex(pub_key_hex)

    try:
        pubkey.verify(signature, plain_text.encode('utf-8'))
    except InvalidSignature:
        return False
    else:
        return True


def ed25519_private_key_format(private_key):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    return private_bytes.hex()


def ed25519_public_key_format(pub_key):
    public_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return public_bytes.hex()


def get_share_secret_from_hex(private_key_hex: str, target_public_key_hex: str, out_format="hex"):
    x25519_prviate_key = x25519.get_prviate_key_from_ed25519_hex(private_key_hex)
    x25519_public_key = x25519.get_public_key_from_ed25519_hex(target_public_key_hex)

    bytes_secret = x25519_prviate_key.exchange(x25519_public_key)

    if out_format == "hex":
        return bytes_secret.hex()
    elif bytes_secret == "base64":
        return base64.b64encode(bytes_secret).decode('utf-8')
    else:
        return bytes_secret
