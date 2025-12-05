# 🔐 Password Manager

### Version: **1.2.0**

A secure and simple **Password Manager** built as part of a university **Cryptography Project**.  
It uses **AES-GCM encryption**, **Scrypt key derivation**, and **salted hashing** to safely store and manage user credentials.

---

## 📌 Project Overview

This project demonstrates practical use of applied cryptography by building a functional password manager that securely stores credentials using modern cryptographic techniques.  
All passwords are protected by a **Master Password**, which is never stored.  
Instead, a cryptographic key is derived using Scrypt (memory-hard KDF), ensuring strong resistance against brute-force attacks.

---

## 🎯 Features

### 🔑 **Security Features**

- AES-GCM authenticated encryption for all stored passwords
- Scrypt key-derivation with salt
- Master password verification using SHA-256
- Strong password requirements
- Auto-generation of secure passwords
- Secure storage using SQLite (`vault.db`)

### 🧰 **Functionality**

- Add new platform password
- View saved credentials
- Update username/password
- Auto-generate new password if weak
- Delete platform
- List all saved platforms
- Change master password (re-encrypts whole database)

### 🧩 **CLI Menu**

1.Add Platform
2.View Platform
3.Update Platform
4.Delete Platform
5.List Platforms
6.Change Master Password
7.Exit

---

## 📁 Project Structure

password-manager/
│
├── src/
│ ├── init.py # Initializes vault + master password
│ └── main.py # Main password manager logic
│
├── docs/ # Documentation / screenshots (optional)
├── .gitignore
└── README.md

---

## 🛠 Requirements

- Python **3.9+**
- `cryptography` package  
  Install:

```bash
pip install cryptography


##  Usage Guide

1️⃣ Initialize the Vault (first time only)
python src/init.py
You will set your Master Password here.

2️⃣ Run the Password Manager
python src/main.py
Enter your Master Password to unlock the vault.

3️⃣ Use the options from the menu
Add, view, update, delete, or list platforms.
```
