# coding: utf-8
"""csr."""
from __future__ import unicode_literals

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


ALGORITHM_DICT = {
    'sha1': hashes.SHA1(),
    'sha224': hashes.SHA224(),
    'sha256': hashes.SHA256(),
    'sha384': hashes.SHA384(),
    'sha512': hashes.SHA512()
}


def generate_csr(private_key, critical=False, encoding='pem', algorithm='sha256',
                 backend=default_backend(), **kwargs):
    """Generate x.509 Certificate Signing Request.

    :param datetime not_valid_before: not_valid_before
    :param datetime not_valid_after: not_valid_after
    :param int/None serial_number: serial_number
    :param obj public_key: public_key
    :param obj private_key: private_key
    """
    common_name = kwargs['common_name']
    country_name = kwargs['country_name']
    org_name = kwargs['org_name']
    state_or_province = kwargs['state_or_province']
    locality_name = kwargs['locality_name']
    dns_list = kwargs['dns_list']

    csr_builder = x509.CertificateSigningRequestBuilder()

    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    algorithm = ALGORITHM_DICT[algorithm]

    csr = csr_builder.subject_name(
        subject_name
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(dns_name) for dns_name in dns_list]),
        critical=critical
    ).sign(private_key, algorithm, backend)

    serial_encoding = serialization.Encoding.PEM if encoding == 'pem' else serialization.Encoding.DER

    return csr.public_bytes(serial_encoding)


def generate_self_signed_certificate(
    private_key, days=90, critical=False, algorithm='sha256',
    backend=default_backend(), encoding='pem', **kwargs
):
    common_name = kwargs['common_name']
    country_name = kwargs['country_name']
    email_address = kwargs['email_address']
    org_name = kwargs['org_name']
    state_or_province = kwargs['state_or_province']
    locality_name = kwargs['locality_name']
    dns_list = kwargs['dns_list']

    csr_builder = x509.CertificateBuilder()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    algorithm = ALGORITHM_DICT[algorithm]

    cert = csr_builder.subject_name(
        subject
    ).issuer_name(issuer).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(dns_name) for dns_name in dns_list]),
        critical=critical
    ).sign(private_key, algorithm, backend)

    serial_encoding = serialization.Encoding.PEM if encoding == 'pem' else serialization.Encoding.DER

    return csr.public_bytes(serial_encoding)
