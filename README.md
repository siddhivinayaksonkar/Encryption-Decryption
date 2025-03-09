# Encryption-Dencryption
# Advanced Encryption Application

A secure encryption application built with Qt that implements a custom advanced encryption algorithm. The application provides a user-friendly graphical interface for encrypting and decrypting text using a sophisticated block cipher implementation.

![Image](https://github.com/user-attachments/assets/1d2776dc-c40f-48e0-a1a4-db0f036ca407)



## Features

- Custom 256-bit encryption algorithm
- Block cipher with 16 rounds of encryption
- Secure key handling with:
  - Primary and secondary key derivation
  - Substitution box (S-box) implementation
  - Permutation tables
  - Round constants
- Support for text and hexadecimal input/output
- Modern Qt-based graphical user interface

## Technical Details

The encryption algorithm implements several cryptographic primitives:
- Block Size: 128 bits (16 bytes)
- Key Size: 256 bits (32 bytes)
- Number of Rounds: 16
- Operations per round:
  - Substitution (S-box)
  - Permutation
  - Mixing function
  - Round constant application

## Building the Project

### Prerequisites
- Qt 6.x or later
- C++17 compatible compiler
- CMake 3.16 or later (if building with CMake)

### Build Steps

1. Clone the repository:
```bash
git https://github.com/siddhivinayaksonkar/Encryption-Decryption.git
cd advanced-encryption
```

2. Build using Qt Creator:
   - Open `untitled.pro` in Qt Creator
   - Configure the project for your kit
   - Click Build

## Usage

1. Launch the application
2. Enter your text in the input field
3. Provide an encryption key
4. Click "Encrypt" to encrypt your text or "Decrypt" to decrypt previously encrypted text
5. View the results in hexadecimal or text format

## Security Considerations

This implementation is for educational purposes and demonstrates various cryptographic concepts. For production use, it's recommended to use established encryption standards like AES.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---
