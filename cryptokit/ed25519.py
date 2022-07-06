# coding: utf-8
"""Ed25519"""
from __future__ import unicode_literals

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import raw_ed25519


def generate_ed25519_key_pair():
    private_key = raw_ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


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
