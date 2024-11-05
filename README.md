# FileSecure

FileSecure is a robust and secure file encryption and decryption tool that utilizes the Secure Modular Transformation Algorithm (SMTA) to protect sensitive information. By leveraging a password-based approach, FileSecure ensures that your files remain confidential and secure. The application employs PBKDF2 for key derivation and a unique modular transformation algorithm for file encryption. With a user-friendly graphical user interface (GUI) built using Tkinter, FileSecure is accessible to users of all skill levels.

### Features

- **File Encryption & Decryption**: 
  - Easily encrypt and decrypt files with a secure password. The encryption process transforms your original files into unreadable formats that can only be reverted back to their original state with the correct password.

- **Secure Modular Transformation Algorithm (SMTA)**:
  - The core of FileSecure’s encryption mechanism. SMTA employs a modular transformation technique to manipulate file bytes, ensuring high security while maintaining efficiency during encryption and decryption processes.

- **Strong Password Security**: 
  - FileSecure uses the PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256 hashing. This method applies a cryptographic salt and multiple iterations to create a strong key from your password, significantly improving security against brute-force attacks.

- **Graphical User Interface**: 
  - A clean and intuitive GUI built with Tkinter allows users to navigate the application easily, making encryption and decryption straightforward tasks.

- **Progress Indicator**: 
  - An animated progress feedback system keeps users informed during the encryption and decryption processes, allowing you to monitor progress visually.

- **Cross-Platform Compatibility**: 
  - FileSecure is designed to run on any operating system that supports Python and Tkinter, including Windows, macOS, and Linux.

### Requirements

- **Python 3.x**: Make sure you have Python 3 installed on your machine.
- **Tkinter**: Typically included with Python installations. Ensure it is available in your environment.
- No external libraries are required as the application utilizes built-in Python libraries.

### Usage

1. **Launching the Application**:
   - After running the command, the FileSecure main menu will appear with options to either encrypt or decrypt files.

2. **Encrypting a File**:
   - Click on the **Encrypt** button to navigate to the encryption page.
   - Select the file you wish to encrypt by clicking the **Select File for Encryption** button.
   - Enter a secure password (minimum of 12 characters) in the designated field.
   - Click the **Encrypt File** button to start the encryption process. The application will provide a progress indicator to show you the status of the operation.
   - Upon successful encryption, the encrypted file will be saved with a .enc extension at your specified location.

3. **Decrypting a File**:
   - Click on the **Decrypt** button to navigate to the decryption page.
   - Select the encrypted file by clicking the **Select Encrypted File** button.
   - Enter the password used during the encryption process to unlock the file.
   - Click the **Decrypt File** button to initiate the decryption process. Again, the application will show a progress indicator during this operation.
   - Once completed, the decrypted file will be saved in your chosen location.

### Security Note

To ensure the security of your encrypted files, it is crucial to use strong and unique passwords. A recommended minimum password length is 12 characters, combining uppercase and lowercase letters, numbers, and special characters. FileSecure does not store passwords or sensitive information, providing an additional layer of security.

### Contribution

Contributions to FileSecure are highly encouraged! If you would like to contribute, please follow these steps:
- Fork the repository to your own GitHub account.
- Make your changes or enhancements.
- Submit a pull request with a description of your modifications.

### Acknowledgements

- Special thanks to the developers of Python and Tkinter for providing the tools needed to create this project.
- Inspired by best practices in cryptography and secure file handling.

### Contact

For any inquiries, suggestions, or feedback regarding the FileSecure project, please feel free to contact me at officialakashak@gmail.com. I appreciate any input that can help improve this tool.

---

This README now highlights the use of the Secure Modular Transformation Algorithm (SMTA) and offers a comprehensive overview of the FileSecure project, including its features, installation, and usage instructions. Be sure to replace placeholders with your actual contact information and repository details.
