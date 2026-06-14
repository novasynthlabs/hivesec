# HiveSec v7.0 Stable iOS

**Official release from NovaSynth Labs**

<img width="1716" height="963" alt="image" src="https://github.com/user-attachments/assets/e3ed3b0f-0dac-4474-9b39-61387c590915" />


A secure, local password vault for iOS built with native Apple encryption and Face ID protection. Designed for personal use with a strong focus on privacy and simplicity.

---

## Description

HiveSec is a lightweight, local-first password manager that runs directly in **Pythonista** on iOS. It uses Apple’s native `CCCrypt` (AES-128) for encryption and supports Face ID for protecting sensitive actions such as deleting entries or changing the master password.

This is **v7.0 Stable** — a fully functional and tested release. Future versions (v8+) are planned as proper compiled native applications that will no longer require Pythonista.

---

## Features

- Native iOS AES-128 encryption via `CCCrypt`
- Strong key derivation using PBKDF2-HMAC-SHA256 (100,000 iterations)
- Face ID protection on Delete Entry and Change Master Password
- Fully local encrypted storage (nothing is sent to the cloud)
- Password generator (8 or 13 character options)
- Search and organize entries by type (Password, Email, Address, Phone, Other)
- Clean, slow-printed interface with emoji-enhanced UX

---

## Security Model

HiveSec v7.0 uses native iOS encryption and local storage only. No data ever leaves your device.

**What protects your data:**
- Native Apple `CCCrypt` AES-128 encryption
- PBKDF2 key derivation with 100,000 iterations
- Face ID required for destructive actions when enabled
- Master password is never stored in plaintext

**Important Limitations:**

<img width="1152" height="768" alt="image" src="https://github.com/user-attachments/assets/55944f66-fccd-435e-a589-9fa141f3a08f" />


- This is a **Python script**, not a compiled native app. The full source code is readable to anyone who obtains the `.py` file.
- Requires **Pythonista** to run.
- Does not currently use the Secure Enclave for key storage.
- No code obfuscation or anti-tampering protections are applied.
- This is the first usable version. Future releases will be significantly more hardened.

For most personal use cases with a strong master password and Face ID enabled, HiveSec provides reasonable protection for local credential storage.

---

## Requirements

- iOS device with **Pythonista** installed
- Face ID / Touch ID capable device (recommended)

---

## Installation & Running

1. Download `HiveSec_v7.py` from the Releases section.
2. Open the file in **Pythonista**.
3. Run the script.
4. Create a strong master password on first launch.
5. (Optional but recommended) Enable Face ID via option 8 on first use.

---

## How Face ID Works

When you first launch HiveSec, you will see option **8. Implement Face ID ?**

- Choosing **YES** enables Face ID protection for Delete Entry and Change Master Password. This option then disappears permanently from the menu.
- Choosing **NO** disables Face ID and also removes the option permanently.
- Choosing **LATER** keeps the option available for a future decision.

Once enabled, Face ID will be required before any sensitive action can be completed.

---

## Limitations & Future Plans

HiveSec v7.0 is a working, usable password vault built for Pythonista. It is **not** yet a standalone native application.

Future versions (v8 and beyond) will be developed as proper compiled iOS applications with improved security architecture, including potential Secure Enclave integration and removal of the Pythonista dependency.

This release represents the stable foundation. All core functionality has been tested thoroughly.

---

## License

© 2026 NovaSynth Labs. All rights reserved.

This source code is provided for **personal viewing and running only**. 

Redistribution, modification, commercial use, or incorporation of this code into other projects is **not permitted** without explicit written permission from NovaSynth Labs.

GitHub Issues and Discussions remain open for bug reports, feedback, and questions.

---

## Credits

**HiveSec v7.0** was developed by **NovaSynth Labs** in collaboration with Grok (xAI) as both coding partner and technical teacher.

---

## Official Links

- **NovaSynth Labs** – Official source of this release
- GitHub Repository: [github.com/novasynthlabs/hivesec](https://github.com/novasynthlabs/hivesec)

<img width="1177" height="403" alt="image" src="https://github.com/user-attachments/assets/ed362c5d-6d51-43b1-a25d-35ffda31a38c" />
