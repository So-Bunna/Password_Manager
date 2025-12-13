import string
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32


def is_strong_password(pwd: str) -> bool:
    if len(pwd) < 8:
        return False
    if not any(c.islower() for c in pwd):
        return False
    if not any(c.isupper() for c in pwd):
        return False
    if not any(c.isdigit() for c in pwd):
        return False
    if not any(c in string.punctuation for c in pwd):
        return False
    return True


def generate_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


def derive_master_key(password: bytes, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=SCRYPT_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    ).derive(password)


def verify_master_password(password: bytes, salt: bytes, verifier: str):
    try:
        key = derive_master_key(password, salt)
    except Exception:
        return None

    digest = hashlib.sha256(key).hexdigest()
    return key if hmac.compare_digest(digest, verifier) else None
