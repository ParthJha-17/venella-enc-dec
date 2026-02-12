# Secure File Vault (Python + SQLite + HTML)

This project implements the abstract's core goals:
- secure file storage using **AES-256 encryption**
- secure password handling with **PBKDF2-HMAC-SHA256 hashing + salt**
- user authentication and access control
- basic access logging for accountability

## Stack
- Python standard library web server (`http.server`)
- SQLite (`sqlite3`)
- HTML/CSS frontend
- OpenSSL CLI for AES encryption/decryption

## Features
- Register/Login/Logout
- Upload file -> encrypted at rest (`vault_storage/`)
- Download file -> decrypted on demand (owner only)
- SHA-256 integrity verification on download
- Access logs for register/login/upload/download/logout events

## Run
```bash
python app.py
```
Open: `http://localhost:5000`

## Security Notes
- File encryption uses `openssl enc -aes-256-cbc -pbkdf2 -salt`.
- Passwords are never stored in plain text.
- Access control checks file ownership before download.
- This is an educational prototype and can be extended with HTTPS, CSRF protection, secure key wrapping, and admin audit pages.
