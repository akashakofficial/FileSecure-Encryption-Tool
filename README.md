# FileSecure

FileSecure is a GUI-based Python application for encrypting and decrypting files using a secure password. This application uses SHA-256 hashing and Base64 encoding for secure and reversible file encryption, ensuring privacy and protection for your files.

## Features

- **File Encryption**: Encrypt files using a password with a minimum length of 12 characters.
- **File Decryption**: Decrypt previously encrypted files with the correct password.
- **SHA-256 Password Hashing**: The password is hashed and encoded to secure the encryption/decryption process.
- **Intuitive UI**: User-friendly interface with simple navigation between main, encryption, and decryption screens.
- **Progress Indicator**: Animated progress indicator during file processing.

## Requirements

- **Python 3.x**
- **Tkinter**: (usually pre-installed with Python)
- **NumPy**
- **Hashlib**

Install any additional dependencies using pip:

```bash
pip install numpy
```

## Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/FileSecure.git
   cd FileSecure
   ```

2. **Run the Application**:
   ```bash
   python app.py
   ```

3. **Encrypting a File**:
   - Select “Encrypt” on the main page.
   - Choose a file for encryption.
   - Enter a secure password (at least 12 characters).
   - Click “Encrypt” to save the encrypted file with a `.bin` extension.

4. **Decrypting a File**:
   - Select “Decrypt” on the main page.
   - Choose the `.bin` encrypted file.
   - Enter the correct password.
   - Click “Decrypt” to save the decrypted file.

## FileSecure GUI

The application has three main pages:

- **Main Page**: Choose to encrypt or decrypt a file.
- **Encryption Page**: Select a file, enter a password, and encrypt.
- **Decryption Page**: Select an encrypted file, enter a password, and decrypt.

## Security Notes

- **Password Requirements**: A minimum of 12 characters is required for a strong password.
- **SHA-256 Hashing**: SHA-256 ensures password security by hashing before encryption/decryption.

## Contributing

Contributions are welcome! To contribute:

1. Fork this repository.
2. Create a new branch for your feature.
3. Submit a pull request with a description of your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

### Screenshot

Add a screenshot here of the main page and encryption/decryption interface to demonstrate the GUI.

---

### Disclaimer

This software is provided for educational purposes. Use FileSecure responsibly, and always test your encryption and decryption processes on non-critical data before applying it to important files.

---

Feel free to reach out with any issues or questions, and thank you for using FileSecure!
