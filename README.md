# 🔒 KhoaCrypt Pro - Encryption Toolkit v1.0

!

**Author:** Phan Phạm Vũ Khoa (Phan Pham Vu Khoa)  
**Field of Study:** Computer Networking and Communications  
**Version:** v1.0

## 💡 Project Overview

**KhoaCrypt Pro** is a robust and user-friendly file and folder encryption/decryption utility built with Python and Tkinter (styled with `ttkbootstrap`). Focused on performance and security, it offers three industry-standard, high-strength cryptographic algorithms, making it an ideal tool for protecting personal and professional data.

## 🌟 Key Features

* **Professional-Grade Cryptography:** Supports modern and recommended authenticated encryption algorithms:
    * **AES-256-GCM (Recommended):** The current standard for authenticated encryption.
    * **ChaCha20-Poly1305 (Fast):** An efficient, high-speed alternative optimized for platforms with limited resources (e.g., Raspberry Pi 5).
    * **AES-256-CBC + HMAC:** A combination providing both confidentiality and integrity assurance.
* **Strong Key Derivation (PBKDF2):** Uses PBKDF2 with SHA-256 and customizable iteration counts (up to 600,000) to drastically slow down brute-force password attacks.
* **Thread-Safe Operations:** Encryption, decryption, and hash calculation run on a **background thread** to ensure the User Interface (UI) remains responsive and avoids freezing during large file operations.
* **Batch Processing:** Capable of recursively encrypting or decrypting entire folder structures.
* **Multi-language Support:** Defaults to **English** with the option to switch to **Vietnamese** in the settings.
* **Integrated Utilities:** Automatically computes and displays **MD5** and **SHA-256** Hashes for the input file, along with a quick copy button for verification.

## 🖥️ System Requirements

* Python 3.7+
* An operating system with Tkinter support (Windows, macOS, Linux).

📝 Basic Usage Guide
Select Input: Use the "Select File" or "Select Folder" buttons, or simply Drag & Drop the file/folder onto the path entry field.

Configure Output: Specify the "Destination" folder and the output filename/prefix.

Choose Algorithm & Key Strength: In the "Encryption Options," select the desired algorithm (AES-256-GCM is recommended) and the Key Derivation Strength (Recommended is optimal for security/speed balance).

Execute: Click "🔒 ENCRYPT" or "🔑 DECRYPT" and enter your password.

Note: The progress bar and status line will provide real-time feedback on the operation.

⚙️ Customization (Settings)
Language: Easily toggle between English and Vietnamese.

Theme: Switch between Darkly (Dark Mode) and Flatly (Light Mode).

## 🤝 Contact and Development
I welcome contributions, bug reports, or inquiries related to this project, particularly in the context of my studies in Computer Networking and Communications, and my focus on building an Emergency Response System and Personal Blog on a Raspberry Pi 5.

Author: Phan Phạm Vũ Khoa

Contact: [Your preferred contact method, e.g., GitHub Issues]
