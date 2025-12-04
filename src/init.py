# src/init.py
"""
Initialization script for the password manager.
Creates the database and prompts for a master password on first run.
"""

import sqlite3
import pathlib
import getpass
import secrets
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# ---- Store DB inside project folder ----
DB_PATH = pathlib.Path(__file__).resolve().parent / "vault.db"

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32


# Safe password prompt for Windows
def safe_input_password(prompt="Password: "):
    try:
        return getpass.getpass(prompt)
    except:
        return input(prompt)


def _derive_master_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password)


def _create_schema(conn: sqlite3.Connection):
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verifier TEXT NOT NULL,
            kdf_params TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            algo TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            aad BLOB,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    conn.commit()


def setup_master_password():
    if DB_PATH.exists():
        print("Vault already exists. Delete vault.db to reset.")
        return

    pw1 = safe_input_password("Create master password: ").encode()
    pw2 = safe_input_password("Confirm master password: ").encode()

    if pw1 != pw2:
        print("Passwords do not match.")
        return

    salt = secrets.token_bytes(16)
    key = _derive_master_key(pw1, salt)
    verifier = hashlib.sha256(key).hexdigest()

    params = str({"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P})

    conn = sqlite3.connect(DB_PATH)
    _create_schema(conn)

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO config (id, salt, verifier, kdf_params) VALUES (1, ?, ?, ?);",
        (salt, verifier, params)
    )

    conn.commit()
    conn.close()

    print("Master password created successfully!")


if __name__ == "__main__":
    setup_master_password()
