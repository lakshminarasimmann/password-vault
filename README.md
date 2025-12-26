# 🔐 Secure Offline Password Manager (Raspberry Pi Appliance)

A **secure, offline-first desktop password manager** built in Python and designed to run as a **dedicated security appliance on Raspberry Pi**.
All credentials are encrypted locally using strong cryptographic primitives and never leave the device.

---

## 🚀 Overview

This project demonstrates how to build a **security-focused desktop application** with strong encryption, proper threat modeling, and hardware-aware deployment.
Unlike cloud-based password managers, this application is **completely offline**, making it suitable for trusted local environments.

---

## ✨ Features

### 🔑 Password Management

* Master password–protected vault
* Add, edit, delete, and search credentials
* Secure password generator
* Show / hide password toggle

### 🔐 Security

* AES-256 encryption (Fernet)
* PBKDF2-HMAC-SHA256 key derivation (300,000 iterations)
* Random per-vault salt
* Encrypted storage at rest
* No cloud, no APIs, no network usage

### 🛡️ Protection Mechanisms

* Auto-lock after inactivity
* Clipboard auto-clear to prevent leakage
* Password age tracking (rotation awareness)
* Security audit for weak and reused passwords

### 🖥️ Platform-Aware Design

* Desktop UI built with Tkinter
* Optimized for Raspberry Pi (ARM Linux)
* Designed as a **local security appliance**, not a generic desktop app

---

## 🧠 Why Raspberry Pi?

This project intentionally leverages **Raspberry Pi** as a hosting platform:

* Always-on local security device
* Physically isolated from cloud threats
* Minimal attack surface
* Suitable for kiosk-style or personal vault usage

The Raspberry Pi acts as a **trusted offline security appliance**.

---

## 🏗️ Architecture

User
↓
Tkinter Desktop UI
↓
Master Password
↓
PBKDF2-HMAC-SHA256 (Key Derivation)
↓
AES-256 Encryption
↓
Encrypted Vault File (Local Disk)

---

## 📂 Project Structure

password_manager/
├── main.py           – GUI + application logic
├── crypto_utils.py   – Encryption & key derivation
├── vault.json.enc    – Encrypted vault (auto-created)
└── README.md

---

## ⚙️ Installation

### Clone the Repository

git clone [https://github.com/your-username/secure-offline-password-manager.git](https://github.com/your-username/secure-offline-password-manager.git)
cd secure-offline-password-manager

### Create Virtual Environment

python3 -m venv venv
source venv/bin/activate

### Install Dependencies

pip install cryptography

Tkinter is included with Python by default.

---

## ▶️ Usage

Run the application:
python main.py

### First Run

* Create a **master password**
* Encrypted vault file is initialized

### Subsequent Runs

* Enter the master password to unlock the vault

⚠️ **No password recovery exists by design.**
If the master password is lost, the vault cannot be recovered.

---

## 🔍 Security Audit

The built-in audit identifies:

* Weak passwords
* Reused passwords
* Old passwords that should be rotated

This mirrors **enterprise password hygiene practices**.

---

## 🛡️ Threat Model (Summary)

### Assets

* Master password
* Encrypted vault
* Clipboard contents

### Threats Mitigated

* Offline brute-force attacks
* Shoulder surfing
* Clipboard leakage
* Unauthorized physical access

### Assumptions

* Operating system integrity is trusted
* Attacker does not have live memory access

---

## 📈 Resume-Ready Description

Built a secure offline password manager in Python using AES-256 encryption and PBKDF2 key derivation, featuring auto-locking vault access, password auditing, and a Raspberry Pi–based security appliance architecture.

---

## 🚀 Future Enhancements

* Encrypted export / import
* Auto-start on Raspberry Pi boot (systemd)
* GPIO hardware lock button
* `.deb` installer packaging
* Multi-user vault support
* Biometric unlock via external hardware

---

## ⚠️ Disclaimer

This project is intended for **educational and personal use**.
No recovery mechanism exists for the master password by design.

---

## 👨‍💻 Author

S Lakshmi Narasimman
Computer Science - AI & ML
Security-Focused Systems Project

---

## ⭐ Support

If you find this project useful:

* ⭐ Star the repository
* 🍴 Fork and extend it
* 🛠️ Experiment with Raspberry Pi hardware integrations

---


