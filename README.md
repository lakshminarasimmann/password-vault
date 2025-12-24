🔐 Secure Offline Password Manager (Raspberry Pi Appliance)

A secure, offline-first desktop password manager built with Python, designed to run as a dedicated security appliance on Raspberry Pi.
All credentials are encrypted locally using strong cryptography and never leave the device.

✨ Features
🔑 Core Password Management

Master password–protected vault

Add, edit, delete, and search credentials

Secure password generator

Show / hide password toggle

🔐 Security

AES-256 encryption (Fernet)

PBKDF2-HMAC-SHA256 key derivation (300,000 iterations)

Random per-vault salt

Encrypted storage at rest

No cloud, no network usage

🛡️ Protection Mechanisms

Auto-lock after inactivity

Clipboard auto-clear (prevents leakage)

Password age tracking (rotation awareness)

Security audit (weak / reused passwords)

🖥️ Platform-Aware Design

Desktop UI built with Tkinter

Optimized for Raspberry Pi (ARM Linux)

Designed as an offline security appliance, not a generic app

🧠 Why Raspberry Pi?

This project intentionally leverages Raspberry Pi as a hosting platform:

Always-on local security device

Physically isolated from cloud threats

No background services or third-party APIs

Suitable for kiosk-style or personal vault use

The Raspberry Pi acts as a trusted local security appliance, not just a development environment.

🏗️ Architecture
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

📂 Project Structure
password_manager/
│
├── main.py           # GUI + application logic
├── crypto_utils.py   # Encryption & key derivation
├── vault.json.enc    # Encrypted vault (auto-created)
└── README.md

⚙️ Installation
1️⃣ Clone Repository
git clone https://github.com/your-username/secure-offline-password-manager.git
cd secure-offline-password-manager

2️⃣ Create Virtual Environment
python3 -m venv venv
source venv/bin/activate

3️⃣ Install Dependencies
pip install cryptography


Tkinter is included with Python by default.

▶️ Usage
python main.py

First Run

Create a master password

Encrypted vault is initialized

Subsequent Runs

Enter master password to unlock vault

⚠️ No password recovery exists by design.
Losing the master password permanently locks the vault.

🔍 Security Audit

The built-in audit identifies:

Weak passwords

Reused passwords

Old passwords (rotation reminder)

This mirrors enterprise password hygiene practices.

🛡️ Threat Model (Summary)

Threats Mitigated

Offline brute-force attempts

Shoulder surfing

Clipboard leakage

Unauthorized physical access

Assumptions

Operating system integrity is trusted

No live memory access by attacker

🚀 Future Enhancements

Encrypted export / import

Auto-start on Raspberry Pi boot (systemd)

GPIO hardware lock button

.deb installer packaging

Multi-user vaults

Biometric unlock (external module)

⚠️ Disclaimer

This project is for educational and personal use.
No recovery mechanism exists for the master password by design.

👨‍💻 Author

S Lakshmi Narasimman


⭐ Support

If you find this project useful:

⭐ Star the repository

🍴 Fork and extend

🛠️ Experiment with Raspberry Pi hardware features
