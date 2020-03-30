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
>>> from cryptokit import RSACrypto
>>> private_key = RSACrypto.generate_private_key(2048)
>>> public_key = private_key.public_key()
>>> message = 'Hello cryptokit'
>>> ciphertext = RSACrypto.encrypt(message, public_key, algorithm='sha256')
>>> plaintext = RSACrypto.decrypt(ciphertext, private_key, algorithm='sha256')
>>> plaintext == message
True
```

## PFX usage

```python
>>> from cryptokit import load_pfx, get_pubkey_from_pfx
>>> pkcs12 = load_pfx(pfx_file, password='password')
>>> cert = pkcs12.get_certificate()
>>> pubkey = get_pubkey_from_pfx(pfx_file, password='password')
# or use cert get pubkey
>>> pubkey = cert.get_pubkey().to_cryptography_key()

>>> from cryptokit import generate_pfx
>>> pfx_data = generate_pfx(cert, friendly_name, private_key)
```

## Create csr

```python
from cryptokit import generate_csr
from cryptokit.rsa import RSACrypto

private_key = RSACrypto.generate_private_key(2048)
payload = {
    'country_name': 'US',
    'state_or_province': 'California',
    'locality_name': 'San Francisco',
    'org_name': 'My Company',
    'common_name': 'mysite.com',
    'dns_list': ['mysite.com', 'www.mysite.com', 'subdomain.mysite.com']
}

csr_data = generate_csr(private_key, encoding='pem', algorithm='sha256', **payload)

with open('/path/to/csr.pem', 'wb') as f:
    f.write(csr_data)
```

# ChangeLog

[changelog](changelog.md)

# License

MIT. See [LICENSE](https://github.com/istommao/cryptokit/blob/master/LICENSE) for more details.
