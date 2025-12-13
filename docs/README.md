# 🔐 Secure Password Manager (AES-GCM + Scrypt)

## 📌 Project Overview

This project is a **secure command-line password manager** written in Python. It allows users to safely store, retrieve, update, and delete account credentials using modern cryptographic techniques.

The application protects all stored passwords using:

- **Scrypt** for secure master key derivation
- **AES-GCM** for authenticated encryption
- **SQLite** as an encrypted local storage backend

The master password is **never stored**. All sensitive data is encrypted before being written to disk.

---

## 🎯 Project Goals

- Prevent plaintext password storage
- Protect against brute-force and offline attacks
- Apply real-world cryptographic best practices
- Demonstrate understanding of hashing, KDFs, and symmetric encryption

---

## 🧱 Project Structure

```
password-manager/
├── src/
│   ├── __init__.py
│   ├── init.py          # Vault initialization & master password setup
│   ├── main.py          # Main application (CRUD operations)
│   └── crypto_utils.py  # Cryptographic utilities (KDF, password checks)
│
├── vault.db             # Encrypted password database (auto-generated)
├── README.md
└── requirements.txt
```

---

## 🔐 Cryptographic Design

### 1. Master Password Protection

- Master password is processed using **Scrypt** (memory-hard KDF)
- A random **salt** is generated and stored
- A SHA-256 verifier of the derived key is used for authentication

### 2. Data Encryption

- Password entries are encrypted using **AES-GCM**
- Each entry uses a unique random nonce
- Platform name is used as **AAD (Additional Authenticated Data)** to bind ciphertext to context

### 3. Security Features

- Strong password enforcement
- Constant-time comparison (`hmac.compare_digest`)
- Brute-force protection (limited attempts)
- Secure random number generation (`secrets` module)

---

## ⚙️ Installation & Setup

### 1. Requirements

- Python 3.9+
- Required libraries:

```bash
pip install cryptography
```

### 2. Initialize Vault

Run once to create the encrypted database and master password:

```bash
python src/init.py
```

---

## ▶️ Running the Application

```bash
python src/main.py
```

### Available Features

- Add new platform credentials
- View stored credentials
- Update usernames or passwords
- Delete entries
- List saved platforms
- Change master password (re-encrypts all data)

---

## 📖 Usage Example

```
Select: 1
Platform: Gmail
Username: example@gmail.com
Auto-generate password: Yes
[+] Added: Gmail
```

---

## 🚀 Future Improvements

- Clipboard auto-clear after copying passwords
- GUI version (Tkinter / Web UI)
- Encrypted cloud backup
- Hardware-backed key storage

---

## 📚 References

- NIST SP 800-63B (Digital Identity Guidelines)
- RFC 4106 – Galois/Counter Mode (GCM)
- OWASP Password Storage Cheat Sheet
- Python Cryptography Documentation

---

## 👤 Author

Student Project – Cryptography / Security Course

**Final Version:** `v1.1.0-final`
