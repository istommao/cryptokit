[![Build Status](https://travis-ci.org/istommao/cryptokit.svg?branch=master)](https://travis-ci.org/istommao/cryptokit)
[![codecov](https://codecov.io/gh/istommao/cryptokit/branch/master/graph/badge.svg)](https://codecov.io/gh/istommao/cryptokit)
[![PyPI](https://img.shields.io/pypi/v/cryptokit.svg)](https://pypi.python.org/pypi/cryptokit)
[![PyPI](https://img.shields.io/pypi/pyversions/Django.svg?style=plastic)](https://pypi.python.org/pypi/cryptokit)

# cryptokit
cryptokit is a cryptography kit base on Cryptography(https://github.com/pyca/cryptography)

# Document

You can find more information in the cryptokit [documentation](http://cryptokit.readthedocs.io/zh/latest/).

# Feature Support
- AES Cryptography
- RSA Cryptography

# Installation

```shell
pip install cryptokit
```

## AES usage

```python
>>> from cryptokit import AESCrypto
>>> message = "hello cryptokit"
>>> crypto = AESCrypto('WDMG1e38igW53YuxkE0SsKUDeLbULAtL', 'm2VYHdx41zRgvg6f')
>>> data = crypto.encrypt(message)
>>> b'\xaa<\x9d\xe9\xde\x0b\xd7\xe9\xfd\xac\xfc\xdd\x9f\xe2V\xd4'
>>> crypto.decrypt(data)
>>> 'hello cryptokit'
```


## RSA usage

```python

```

# ChangeLog

[changelog](changelog.md)

# License

MIT. See [LICENSE](https://github.com/istommao/cryptokit/blob/master/LICENSE) for more details.
