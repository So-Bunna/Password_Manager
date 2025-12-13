import sqlite3
import pathlib
import getpass
import secrets
import hashlib
import os

from crypto_utils import derive_master_key, is_strong_password

DB_PATH = pathlib.Path(__file__).resolve().parent / "vault.db"


def safe_input_password(prompt="Password: "):
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)


def create_schema(conn):
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verifier TEXT NOT NULL
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
        print("Vault already exists.")
        return

    while True:
        pw1 = safe_input_password("Create master password: ")
        pw2 = safe_input_password("Confirm master password: ")

        if pw1 != pw2:
            print("Passwords do not match.\n")
            continue

        if not is_strong_password(pw1):
            print("Weak password! Use uppercase, lowercase, digit, symbol, 8+ chars.\n")
            continue

        break

    pw1 = pw1.encode()
    salt = secrets.token_bytes(16)
    key = derive_master_key(pw1, salt)
    verifier = hashlib.sha256(key).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO config (id, salt, verifier) VALUES (1, ?, ?);",
        (salt, verifier)
    )

    conn.commit()
    conn.close()

    os.chmod(DB_PATH, 0o600)
    print("✔ Vault initialized successfully!")


if __name__ == "__main__":
    setup_master_password()
