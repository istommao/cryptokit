RSA usage
============

RSA相关使用

::

    >>> from cryptokit import RSACrypto
    >>> private_key = RSACrypto.generate_private_key(2048)
    >>> public_key = private_key.public_key()
    >>> message = 'Hello cryptokit'
    >>> ciphertext = RSACrypto.encrypt(message, public_key, algorithm='sha256')
    >>> plaintext = RSACrypto.decrypt(ciphertext, private_key, algorithm='sha256')
    >>> plaintext == message
    True
