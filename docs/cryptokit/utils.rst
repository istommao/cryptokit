Utils usage
============

Utils相关使用

::

    >>> from cryptokit import load_pfx, get_pubkey_from_pfx
    >>> pkcs12 = load_pfx(pfx_file, password='password')
    >>> cert = pkcs12.get_certificate()
    >>> pubkey = get_pubkey_from_pfx(pfx_file, password='password')
    # or use cert get pubkey
    >>> pubkey = cert.get_pubkey().to_cryptography_key()

    >>> from cryptokit import generate_pfx
    >>> pfx_data = generate_pfx(cert, friendly_name, private_key)
