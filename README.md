# 🔒 Secure Password Vault

A professional, encrypted password manager built with Python, Tkinter, and Modern UI (CustomTkinter).

## ✨ Features

- **End-to-End Encryption**: Uses `Fernet` (AES-128 in CBC mode with PKCS7 padding) and `PBKDF2HMAC` for key derivation.
- **Modern UI**: Clean, light-themed interface with professional styling.
- **Categorization**: Organize passwords by Game, Website, Email, Education, etc.
- **Search & Filter**: Real-time filtering of your vault entries.
- **Clipboard Integration**: One-click copy for usernames and passwords.
- **Auto-Setup**: Automatically initializes a secure vault on first run.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- [pip](https://pip.pypa.io/en/stable/installation/)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-vault.git
   cd password-vault
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python project.py
   ```

## 🛠️ Technology Stack

- **GUI**: [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- **Encryption**: [Cryptography.io](https://cryptography.io/en/latest/)
- **Data Storage**: Encrypted JSON files

## 🔒 Security Note

Your data is stored locally in the `vault_data/` directory. 
- `config.json`: Stores your PIN hash and salt.
- `vault.enc`: Stores your encrypted password data.

**Never share your `vault_data` directory or your Master PIN.**

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

## Icon/image Credit

<a href="https://www.flaticon.com/free-icons/cyber" title="cyber icons">Cyber icons created by logisstudio - Flaticon</a>