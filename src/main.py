# src/main.py
import json
import sqlite3
import pathlib
import getpass
import sys
import secrets
import hashlib
import hmac
from typing import Optional, Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend


# ---- FIX getpass for PowerShell ----
def safe_input_password(prompt="Password: "):
    try:
        return getpass.getpass(prompt)
    except:
        return input(prompt)


# ---- Store DB in project folder ----
DB_PATH = pathlib.Path(__file__).resolve().parent / "vault.db"

DEFAULT_SCRYPT_N = 2**14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_SCRYPT_LEN = 32

ALG_AESGCM = "AES-GCM"
ALG_CHACHA20 = "ChaCha20-Poly1305"
ALLOWED_ALGOS = (ALG_AESGCM, ALG_CHACHA20)


def _connect_db():
    if not DB_PATH.exists():
        print("ERROR: Vault not initialized. Run: python src/init.py")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def _get_config(conn) -> Tuple[bytes, str]:
    cur = conn.cursor()
    cur.execute("SELECT salt, verifier, kdf_params FROM config WHERE id = 1;")
    row = cur.fetchone()
    return row[0], row[1]


def _derive_master_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=DEFAULT_SCRYPT_LEN,
        n=DEFAULT_SCRYPT_N,
        r=DEFAULT_SCRYPT_R,
        p=DEFAULT_SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password)


def _verify_master_password(password: bytes, salt: bytes, verifier: str) -> Optional[bytes]:
    try:
        key = _derive_master_key(password, salt)
    except:
        return None

    digest = hashlib.sha256(key).hexdigest()
    if hmac.compare_digest(digest, verifier):
        return key
    return None


def _encrypt_payload(key: bytes, payload: bytes, algo: str, aad: bytes):
    nonce = secrets.token_bytes(12)
    aead = AESGCM(key) if algo == ALG_AESGCM else ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, payload, aad)
    return nonce, ciphertext


def _decrypt_payload(key: bytes, algo: str, nonce: bytes, ciphertext: bytes, aad: bytes):
    aead = AESGCM(key) if algo == ALG_AESGCM else ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, aad)


# ===== CRUD Methods =====
def add_entry(conn, key, name, username, password, algo):
    payload = json.dumps({"username": username, "password": password}).encode()
    aad = name.encode()
    nonce, ciphertext = _encrypt_payload(key, payload, algo, aad)

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO entries (name, algo, nonce, ciphertext, aad)
            VALUES (?, ?, ?, ?, ?)
        """, (name, algo, nonce, ciphertext, aad))
        conn.commit()
        print(f"[+] Added entry '{name}'")
    except sqlite3.IntegrityError:
        print("Entry already exists.")


def view_entry(conn, key, name):
    cur = conn.cursor()
    cur.execute("SELECT algo, nonce, ciphertext, aad FROM entries WHERE name=?;", (name,))
    row = cur.fetchone()

    if not row:
        print("Entry not found.")
        return

    algo, nonce, ciphertext, aad = row
    try:
        plaintext = _decrypt_payload(key, algo, nonce, ciphertext, aad)
        data = json.loads(plaintext.decode())

        print("\n--- VIEW ENTRY ---")
        print("Name:", name)
        print("Username:", data["username"])
        print("Password:", data["password"])
        print()
    except InvalidTag:
        print("Decryption failed.")


def update_entry(conn, key, name, username, password, algo):
    cur = conn.cursor()
    cur.execute("SELECT algo, nonce, ciphertext, aad FROM entries WHERE name=?;", (name,))
    row = cur.fetchone()

    if not row:
        print("Entry not found.")
        return

    old_algo, nonce, ciphertext, aad = row
    old_data = json.loads(_decrypt_payload(key, old_algo, nonce, ciphertext, aad).decode())

    if username:
        old_data["username"] = username
    if password:
        old_data["password"] = password

    new_algo = algo if algo else old_algo
    new_nonce, new_cipher = _encrypt_payload(key, json.dumps(old_data).encode(), new_algo, aad)

    cur.execute("""
        UPDATE entries SET algo=?, nonce=?, ciphertext=?, updated_at=CURRENT_TIMESTAMP
        WHERE name=?
    """, (new_algo, new_nonce, new_cipher, name))

    conn.commit()
    print("[+] Updated.")


def delete_entry(conn, name):
    cur = conn.cursor()
    cur.execute("DELETE FROM entries WHERE name=?;", (name,))
    conn.commit()

    if cur.rowcount:
        print("[+] Entry deleted.")
    else:
        print("Entry not found.")


def list_entries(conn):
    cur = conn.cursor()
    cur.execute("SELECT name, algo, updated_at FROM entries ORDER BY name;")
    rows = cur.fetchall()

    if not rows:
        print("No entries.")
        return

    print("\n--- SAVED ACCOUNTS ---")
    for name, algo, updated in rows:
        print(f"- {name} | Algo: {algo} | Updated: {updated}")
    print()


def change_master_password(conn, old_key):
    new1 = safe_input_password("New master password: ").encode()
    new2 = safe_input_password("Confirm new master password: ").encode()

    if new1 != new2:
        print("Passwords do not match.")
        return

    new_salt = secrets.token_bytes(16)
    new_key = _derive_master_key(new1, new_salt)
    new_verifier = hashlib.sha256(new_key).hexdigest()

    cur = conn.cursor()
    cur.execute("SELECT id, name, algo, nonce, ciphertext, aad FROM entries;")
    rows = cur.fetchall()

    for _id, name, algo, nonce, ciphertext, aad in rows:
        plaintext = _decrypt_payload(old_key, algo, nonce, ciphertext, aad)
        new_nonce, new_cipher = _encrypt_payload(new_key, plaintext, algo, aad)
        cur.execute("UPDATE entries SET nonce=?, ciphertext=? WHERE id=?;", (new_nonce, new_cipher, _id))

    cur.execute("UPDATE config SET salt=?, verifier=? WHERE id=1;", (new_salt, new_verifier))
    conn.commit()

    print("[+] Master password updated.")


def prompt_master_key(conn):
    salt, verifier = _get_config(conn)

    for _ in range(5):
        pw = safe_input_password("Master password: ").encode()
        key = _verify_master_password(pw, salt, verifier)
        if key:
            return key
        print("Incorrect password.")
    print("Too many attempts.")
    sys.exit(1)


# ===== MAIN MENU =====
def main():
    conn = _connect_db()
    key = prompt_master_key(conn)

    while True:
        print("\n====== PASSWORD MANAGER ======")
        print("1. Add Account")
        print("2. View Account")
        print("3. Update Account")
        print("4. Delete Account")
        print("5. List Accounts")
        print("6. Change Master Password")
        print("7. Exit")
        print("==============================")

        choice = input("Select option: ").strip()

        if choice == "1":
            name = input("Entry name: ")
            username = input("Username: ")
            password = safe_input_password("Password: ")
            algo = input("Algo (AES-GCM / ChaCha20-Poly1305): ").strip()

            if algo not in ALLOWED_ALGOS:
                algo = ALG_AESGCM

            add_entry(conn, key, name, username, password, algo)

        elif choice == "2":
            name = input("Entry name: ")
            view_entry(conn, key, name)

        elif choice == "3":
            name = input("Entry name: ")
            username = input("New username (skip empty): ") or None
            password = safe_input_password("New password (skip empty): ") or None
            algo = input("Algo (AES-GCM / ChaCha20-Poly1305, empty skip): ").strip()
            if algo not in ALLOWED_ALGOS:
                algo = None

            update_entry(conn, key, name, username, password, algo)

        elif choice == "4":
            name = input("Entry name: ")
            delete_entry(conn, name)

        elif choice == "5":
            list_entries(conn)

        elif choice == "6":
            change_master_password(conn, key)
            key = prompt_master_key(conn)

        elif choice == "7":
            print("Goodbye!")
            conn.close()
            sys.exit(0)

        else:
            print("Invalid option.")
if __name__ == "__main__":
    main()
