AES usage
============

AES相关使用

::

    >>> from cryptokit import AESCrypto
    >>> message = "hello cryptokit"
    >>> crypto = AESCrypto('WDMG1e38igW53YuxkE0SsKUDeLbULAtL', 'm2VYHdx41zRgvg6f')
    >>> data = crypto.encrypt(message)
    >>> print(data)
    b'\xaa<\x9d\xe9\xde\x0b\xd7\xe9\xfd\xac\xfc\xdd\x9f\xe2V\xd4'
    >>> crypto.decrypt(data)
    'hello cryptokit'
