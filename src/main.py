import json
import sqlite3
import pathlib
import getpass
import sys
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from crypto_utils import (
    is_strong_password,
    generate_password,
    verify_master_password,
    derive_master_key
)

DB_PATH = pathlib.Path(__file__).resolve().parent / "vault.db"
ALG_AESGCM = "AES-GCM"


def safe_input_password(prompt="Password: "):
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)


def connect_db():
    if not DB_PATH.exists():
        print("Vault not initialized. Run init.py first.")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def get_config(conn):
    cur = conn.cursor()
    cur.execute("SELECT salt, verifier FROM config WHERE id=1;")
    return cur.fetchone()


def encrypt_payload(key, data, aad):
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, data, aad)


def decrypt_payload(key, nonce, ciphertext, aad):
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def prompt_master_key(conn):
    salt, verifier = get_config(conn)

    for _ in range(5):
        pw = safe_input_password("Master password: ").encode()
        key = verify_master_password(pw, salt, verifier)
        if key:
            return key
        print("Incorrect password.")
    sys.exit("Too many attempts.")


# -------- CRUD --------
def get_non_empty_input(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Username cannot be empty.")

def add_entry(conn, key):
    platform = input("Platform: ").strip().lower()
    username = get_non_empty_input("Username: ")
    print("1. Enter password")
    print("2. Auto-generate password")
    mode = input("Choose: ")

    if mode == "1":
        attempts = 0
        while True:
            password = safe_input_password("Password: ")
            if is_strong_password(password):
                break
            attempts += 1
            print("Weak password.")
            if attempts >= 3:
                password = generate_password()
                print("Generated:", password)
                break
    else:
        password = generate_password()
        print("Generated:", password)

    payload = json.dumps({"username": username, "password": password}).encode()
    aad = platform.encode()

    nonce, cipher = encrypt_payload(key, payload, aad)

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO entries (name, algo, nonce, ciphertext, aad)
            VALUES (?, ?, ?, ?, ?)
        """, (platform, ALG_AESGCM, nonce, cipher, aad))
        conn.commit()
        print("Added successfully.")
    except sqlite3.IntegrityError:
        print("Platform already exists.")


def view_entry(conn, key):
    platform = input("Platform: ").strip().lower()
    cur = conn.cursor()
    cur.execute("SELECT nonce, ciphertext, aad FROM entries WHERE name=?", (platform,))
    row = cur.fetchone()

    if not row:
        print("Not found.")
        return

    try:
        data = decrypt_payload(key, *row)
        info = json.loads(data.decode())
        print("\nUsername:", info["username"])
        print("Password:", info["password"])
    except InvalidTag:
        print("Decryption failed.")


def update_entry(conn, key):
    platform = input("Platform: ").strip().lower()
    cur = conn.cursor()
    cur.execute("SELECT id, nonce, ciphertext, aad FROM entries WHERE name=?", (platform,))
    row = cur.fetchone()

    if not row:
        print("Not found.")
        return

    entry_id, nonce, ciphertext, aad = row
    data = json.loads(decrypt_payload(key, nonce, ciphertext, aad).decode())

    # ----- Update username -----
    new_user = input("New username (leave empty to keep): ").strip()
    if new_user:
        data["username"] = new_user


    # ----- Update password -----
    print("\nPassword options:")
    print("1. Enter password manually")
    print("2. Auto-generate strong password")
    print("3. Keep current password")
    choice = input("Choose: ")

    if choice == "1":
        attempts = 0
        while True:
            new_pwd = safe_input_password("New password: ")
            if is_strong_password(new_pwd):
                data["password"] = new_pwd
                break

            attempts += 1
            print("Weak password!")

            if attempts >= 3:
                data["password"] = generate_password()
                print("Auto-generated:", data["password"])
                break

    elif choice == "2":
        data["password"] = generate_password()
        print("Auto-generated:", data["password"])

    # choice == "3" → keep existing password

    # ----- Re-encrypt -----
    new_nonce, new_cipher = encrypt_payload(
        key,
        json.dumps(data).encode(),
        aad
    )

    cur.execute("""
        UPDATE entries
        SET nonce=?, ciphertext=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?
    """, (new_nonce, new_cipher, entry_id))

    conn.commit()
    print("Updated successfully.")



def delete_entry(conn):
    platform = input("Platform: ").strip().lower()
    cur = conn.cursor()
    cur.execute("DELETE FROM entries WHERE name=?", (platform,))
    conn.commit()
    print("Deleted." if cur.rowcount else "Not found.")


def list_entries(conn):
    cur = conn.cursor()
    cur.execute("SELECT name, updated_at FROM entries ORDER BY name;")
    rows = cur.fetchall()

    if not rows:
        print("No entries.")
        return

    for name, updated in rows:
        print(f"- {name} (Updated: {updated})")


def change_master_password(conn, old_key):
    while True:
        new1 = safe_input_password("New master password: ")
        new2 = safe_input_password("Confirm: ")

        if new1 != new2:
            print("Passwords do not match.")
            continue
        if not is_strong_password(new1):
            print("Weak password.")
            continue
        break

    new_salt = secrets.token_bytes(16)
    new_key = derive_master_key(new1.encode(), new_salt)
    new_verifier = hashlib.sha256(new_key).hexdigest()

    cur = conn.cursor()

    try:
        # 🔐 START TRANSACTION
        conn.execute("BEGIN")

        # Re-encrypt all entries
        cur.execute("SELECT id, nonce, ciphertext, aad FROM entries;")
        rows = cur.fetchall()

        for entry_id, nonce, ciphertext, aad in rows:
            plaintext = decrypt_payload(old_key, nonce, ciphertext, aad)
            new_nonce, new_cipher = encrypt_payload(new_key, plaintext, aad)

            cur.execute("""
                UPDATE entries
                SET nonce=?, ciphertext=?
                WHERE id=?
            """, (new_nonce, new_cipher, entry_id))

        # Update config LAST
        cur.execute("""
            UPDATE config
            SET salt=?, verifier=?
            WHERE id=1
        """, (new_salt, new_verifier))

        #  COMMIT ONLY IF ALL SUCCEEDED
        conn.commit()
        print("Master password updated successfully.")
        return new_key

    except Exception as e:
        #  ROLLBACK ON ANY FAILURE
        conn.rollback()
        print("Master password update failed. No changes were applied.")
        return old_key



# -------- MENU --------
def main():
    conn = connect_db()
    key = prompt_master_key(conn)

    while True:
        print("""
1. Add Entry
2. View Entry
3. Update Entry
4. Delete Entry
5. List Entries
6. Change Master Password
7. Exit
""")
        choice = input("Select: ")

        if choice == "1":
            add_entry(conn, key)
        elif choice == "2":
            view_entry(conn, key)
        elif choice == "3":
            update_entry(conn, key)
        elif choice == "4":
            delete_entry(conn)
        elif choice == "5":
            list_entries(conn)
        elif choice == "6":
            key = change_master_password(conn, key)
        elif choice == "7":
            conn.close()
            sys.exit()
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
