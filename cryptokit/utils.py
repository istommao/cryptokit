# coding: utf-8
"""utils."""
from __future__ import unicode_literals

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from OpenSSL import crypto


def load_pfx(pfx_file, password=None):
    """Load pfx file."""
    if not isinstance(pfx_file, bytes):
        with open(pfx_file, 'rb') as file:
            data = file.read()
    else:
        data = pfx_file

    if password and not isinstance(password, bytes):
        password = password.encode('utf-8')

    return crypto.load_pkcs12(data, passphrase=password)


def get_pubkey_from_pfx(pfx_file, password=None):
    """Get pubkey."""
    pkcs12 = load_pfx(pfx_file, password=password)

    cert = pkcs12.get_certificate()
    return cert.get_pubkey().to_cryptography_key()


def generate_certificate(not_valid_before, not_valid_after,
                         serial_number=None, algorithm='sha256', **kwargs):
    """Generate x.509 certificate.

    :param datetime not_valid_before: not_valid_before
    :param datetime not_valid_after: not_valid_after
    :param int/None serial_number: serial_number
    :param obj public_key: public_key
    :param obj private_key: private_key
    """
    common_name = kwargs['common_name']
    country_name = kwargs['country_name']
    email_address = kwargs['email_address']
    org_name = kwargs['org_name']
    state_or_province = kwargs['state_or_province']
    locality_name = kwargs['locality_name']

    algorithm_dict = {
        'sha1': hashes.SHA1(),
        'sha224': hashes.SHA224(),
        'sha256': hashes.SHA256(),
        'sha384': hashes.SHA384(),
        'sha512': hashes.SHA512()
    }
    algorithm = algorithm_dict.get(algorithm)

    builder = x509.CertificateBuilder()

    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name)
    ]))
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, kwargs['company_name']),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address)
    ]))

    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    if not serial_number:
        serial_number = x509.random_serial_number()

    builder = builder.serial_number(serial_number)
    builder = builder.public_key(kwargs['public_key'])

    # builder = builder.add_extension(
    #     x509.SubjectAlternativeName(
    #         [x509.DNSName(common_name)]
    #     ),
    #     critical=False
    # )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    certificate = builder.sign(
        private_key=kwargs['private_key'], algorithm=algorithm,
        backend=default_backend()
    )
    return certificate


def generate_pfx(certificate, friendly_name, private_key, passphrase=None,
                 iterations=2048):
    """Generate pfx.

    :param obj certificate: certificate
    """
    if not isinstance(certificate, crypto.X509):
        certificate = crypto.X509().from_cryptography(certificate)

    if not isinstance(private_key, crypto.PKey):
        private_key = crypto.PKey().from_cryptography_key(private_key)

    if not isinstance(friendly_name, bytes):
        friendly_name = friendly_name.encode('utf-8')

    pkcs12 = crypto.PKCS12()
    pkcs12.set_certificate(certificate)
    pkcs12.set_friendlyname(friendly_name)
    pkcs12.set_privatekey(private_key)

    return pkcs12.export(passphrase=passphrase, iter=iterations, maciter=1)
