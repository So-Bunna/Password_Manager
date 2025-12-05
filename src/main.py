import json
import sqlite3
import pathlib
import getpass
import sys
import secrets
import string
import hashlib
import hmac
from typing import Optional, Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend


# -------- Safe password input --------
def safe_input_password(prompt="Password: "):
    try:
        return getpass.getpass(prompt)
    except:
        return input(prompt)


# -------- Database path --------
DB_PATH = pathlib.Path(__file__).resolve().parent / "vault.db"

DEFAULT_SCRYPT_N = 2**14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_SCRYPT_LEN = 32

ALG_AESGCM = "AES-GCM"


# -------- Password Strength Checker --------
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


# -------- Password Generator --------
def generate_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


# ===== DB =====
def _connect_db():
    if not DB_PATH.exists():
        print("ERROR: Vault not initialized. Run: python src/init.py")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def _get_config(conn):
    cur = conn.cursor()
    cur.execute("SELECT salt, verifier FROM config WHERE id = 1;")
    salt, verifier = cur.fetchone()
    return salt, verifier


def _derive_master_key(password: bytes, salt: bytes):
    return Scrypt(
        salt=salt,
        length=DEFAULT_SCRYPT_LEN,
        n=DEFAULT_SCRYPT_N,
        r=DEFAULT_SCRYPT_R,
        p=DEFAULT_SCRYPT_P,
        backend=default_backend()
    ).derive(password)


def _verify_master_password(password: bytes, salt: bytes, verifier: str):
    try:
        key = _derive_master_key(password, salt)
    except:
        return None

    digest = hashlib.sha256(key).hexdigest()
    return key if hmac.compare_digest(digest, verifier) else None


# ===== Encryption =====
def _encrypt_payload(key: bytes, payload: bytes, aad: bytes):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
    return nonce, ciphertext


def _decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ===== CRUD =====
def add_entry(conn, key, platform, username, password):
    payload = json.dumps({"username": username, "password": password}).encode()
    aad = platform.encode()
    nonce, ciphertext = _encrypt_payload(key, payload, aad)

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO entries (name, algo, nonce, ciphertext, aad)
            VALUES (?, ?, ?, ?, ?)
        """, (platform, ALG_AESGCM, nonce, ciphertext, aad))
        conn.commit()
        print(f"[+] Added: {platform}")
    except sqlite3.IntegrityError:
        print("Platform already exists!")


def view_entry(conn, key, platform):
    cur = conn.cursor()
    cur.execute("SELECT nonce, ciphertext, aad FROM entries WHERE name=?;", (platform,))
    row = cur.fetchone()

    if not row:
        print("Platform not found.")
        return

    nonce, ciphertext, aad = row
    try:
        plaintext = _decrypt_payload(key, nonce, ciphertext, aad)
        data = json.loads(plaintext.decode())

        print("\n--- VIEW PLATFORM ---")
        print("Platform:", platform)
        print("Username:", data["username"])
        print("Password:", data["password"])
        print()
    except InvalidTag:
        print("Decryption failed.")


def update_entry(conn, key, platform, username, password):
    cur = conn.cursor()
    cur.execute("SELECT nonce, ciphertext, aad FROM entries WHERE name=?;", (platform,))
    row = cur.fetchone()

    if not row:
        print("Platform not found.")
        return

    nonce, ciphertext, aad = row
    old_data = json.loads(_decrypt_payload(key, nonce, ciphertext, aad).decode())

    if username:
        old_data["username"] = username
    if password:
        old_data["password"] = password

    new_nonce, new_cipher = _encrypt_payload(key, json.dumps(old_data).encode(), aad)

    cur.execute("""
        UPDATE entries SET nonce=?, ciphertext=?, updated_at=CURRENT_TIMESTAMP
        WHERE name=?
    """, (new_nonce, new_cipher, platform))

    conn.commit()
    print("[+] Updated.")


def delete_entry(conn, platform):
    cur = conn.cursor()
    cur.execute("DELETE FROM entries WHERE name=?;", (platform,))
    conn.commit()

    if cur.rowcount:
        print("[+] Deleted.")
    else:
        print("Platform not found.")


def list_entries(conn):
    cur = conn.cursor()
    cur.execute("SELECT name, updated_at FROM entries ORDER BY name;")
    rows = cur.fetchall()

    print("\n--- SAVED PLATFORMS ---")
    if not rows:
        print("None saved.")
        return
    for name, updated in rows:
        print(f"- {name} (Updated: {updated})")
    print()


# ===== Master Password =====
def change_master_password(conn, old_key):
    while True:
        new1 = safe_input_password("New master password: ")

        # Strong password check
        if not is_strong_password(new1):
            print("❌ Weak password. It must contain:")
            print("- Uppercase")
            print("- Lowercase")
            print("- Digit")
            print("- Symbol")
            print("- Minimum 8 characters\n")
            continue  # Ask again

        new2 = safe_input_password("Confirm: ")

        if new1 != new2:
            print("❌ Passwords do not match. Try again.\n")
            continue  # Ask again

        # Convert to bytes only after confirmed strong & matching
        new1 = new1.encode()
        break  # Exit loop – password accepted

    # ----- Update Master Password -----
    new_salt = secrets.token_bytes(16)
    new_key = _derive_master_key(new1, new_salt)
    new_verifier = hashlib.sha256(new_key).hexdigest()

    cur = conn.cursor()
    cur.execute("SELECT id, name, nonce, ciphertext, aad FROM entries;")
    rows = cur.fetchall()

    # Re-encrypt entries with new key
    for _id, name, nonce, ciphertext, aad in rows:
        plaintext = _decrypt_payload(old_key, nonce, ciphertext, aad)
        new_nonce, new_cipher = _encrypt_payload(new_key, plaintext, aad)
        cur.execute("UPDATE entries SET nonce=?, ciphertext=? WHERE id=?", (new_nonce, new_cipher, _id))

    # Update config
    cur.execute("UPDATE config SET salt=?, verifier=? WHERE id=1;", (new_salt, new_verifier))
    conn.commit()

    print("\n[+] Master password updated successfully!")



def prompt_master_key(conn):
    salt, verifier = _get_config(conn)

    for _ in range(5):
        pw = safe_input_password("Master password: ").encode()
        key = _verify_master_password(pw, salt, verifier)
        if key:
            return key
        print("Incorrect!")
    print("Too many attempts.")
    sys.exit(1)


# ===== MENU =====
def main():
    conn = _connect_db()
    key = prompt_master_key(conn)

    while True:
        print("\n====== PASSWORD MANAGER ======")
        print("1. Add Platform")
        print("2. View Platform")
        print("3. Update Platform")
        print("4. Delete Platform")
        print("5. List Platforms")
        print("6. Change Master Password")
        print("7. Exit")
        print("==============================")

        choice = input("Select: ").strip()

        # ======= ADD PLATFORM =======
        if choice == "1":
            platform = input("Platform (e.g., Facebook, Gmail): ")
            username = input("Username: ")

            # Password selection
            print("\nChoose password option:")
            print("1. Enter password manually")
            print("2. Auto-generate strong password")
            pwd_mode = input("Choose: ")

            if pwd_mode == "1":
                attempts = 0
                while True:
                    pwd = safe_input_password("Password: ")
                    if is_strong_password(pwd):
                        break

                    attempts += 1
                    print("⚠ Weak password! Must include uppercase, lowercase, digit, symbol, 8+ chars.")

                    if attempts >= 3:
                        pwd = generate_password()
                        print(f"\n[!] Too many weak attempts! Auto-generated strong password:")
                        print(f"> {pwd}")
                        break

            else:
                pwd = generate_password()
                print(f"[+] Auto-generated password: {pwd}")

            add_entry(conn, key, platform, username, pwd)

        # ======= VIEW PLATFORM =======
        elif choice == "2":
            platform = input("Platform: ")
            view_entry(conn, key, platform)

        # ======= UPDATE PLATFORM =======
        elif choice == "3":
            platform = input("Platform: ")
            username = input("New username (skip empty): ") or None

            print("\n1. Change password")
            print("2. Auto-generate new password")
            print("3. Skip password update")
            pm = input("Choose: ")

            password = None

            if pm == "1":
                attempts = 0
                while True:
                    newpwd = safe_input_password("New password: ")
                    if is_strong_password(newpwd):
                        password = newpwd
                        break

                    attempts += 1
                    print("Weak password!")

                    if attempts >= 3:
                        password = generate_password()
                        print(f"[!] Too many weak attempts. Auto-generated: {password}")
                        break

            elif pm == "2":
                password = generate_password()
                print(f"[+] New auto-password: {password}")

            update_entry(conn, key, platform, username, password)

        elif choice == "4":
            platform = input("Platform: ")
            delete_entry(conn, platform)

        elif choice == "5":
            list_entries(conn)

        elif choice == "6":
            change_master_password(conn, key)
            key = prompt_master_key(conn)

        elif choice == "7":
            print("Goodbye!")
            conn.close()
            sys.exit()

        else:
            print("Invalid option!")


if __name__ == "__main__":
    main()
