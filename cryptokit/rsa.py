"""rsa crypto."""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSACrypto(object):
    """RSACrypto."""

    ALGORITHM_DICT = {
        'sha1': hashes.SHA1(),
        'sha224': hashes.SHA224(),
        'sha256': hashes.SHA256(),
        'sha384': hashes.SHA384(),
        'sha512': hashes.SHA512()
    }

    @staticmethod
    def generate_private_key(key_size):
        """Generate rsa private key."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        return private_key

    @staticmethod
    def dump_private_key_pem(private_key):
        """Dump private key pem."""
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode()

    @staticmethod
    def dump_public_key_pem(public_key):
        """Dump public key pem."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()

    @classmethod
    def signing(cls, message, private_key, algorithm='sha1'):
        """signing."""
        if not isinstance(message, bytes):
            message = message.encode()

        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        signer = private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm
        )

        signer.update(message)
        return signer.finalize()

    @classmethod
    def verification(cls, message, signature, public_key, algorithm='sha1'):
        """Verification."""
        if not isinstance(message, bytes):
            message = message.encode()

        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        verifier = public_key().verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm
        )
        verifier.update(message)
        return verifier.verify()

    @classmethod
    def encrypt(cls, message, public_key, algorithm='sha1'):
        """Public key encrypt."""
        if not isinstance(message, bytes):
            message = message.encode()

        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=algorithm),
                algorithm=algorithm,
                label=None
            )
        )
        return ciphertext

    @classmethod
    def decrypt(cls, ciphertext, private_key, algorithm='sha1'):
        """Private key descrption."""
        algorithm = cls.ALGORITHM_DICT.get(algorithm)

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=algorithm),
                algorithm=algorithm,
                label=None
            )
        )
        return plaintext.decode()
