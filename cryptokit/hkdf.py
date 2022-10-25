import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


sha_map = {
    "sha256": hashes.SHA384(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


def get_hkdf_derive_key(input_key, salt="", info="", length=32, algorithm="sha256", out_format="base64"):
    if not isinstance(input_key, bytes):
        raise ValueError("Invalid input key type")

    hkdf = HKDF(
        algorithm=sha_map.get(algorithm),
        length=length,
        salt=salt.encode("utf-8"),
        info=info.encode("utf-8"),
    )

    bytes_key = hkdf.derive(input_key)

    if out_format == "base64":
        return base64.b64encode(bytes_key).decode("utf-8")
    else:
        return bytes_key
