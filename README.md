# CryptoToolkit

A comprehensive cryptography toolkit that demonstrates various encryption techniques and cryptographic primitives.

## Features

- Symmetric encryption (AES, ChaCha20)
- Asymmetric encryption (RSA)
- Digital signatures
- Secure key derivation
- Password hashing
- File encryption/decryption
- Message authentication (HMAC)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Symmetric Encryption

```bash
python crypto_toolkit.py symmetric-encrypt --algorithm aes --input "Hello, World!" --password "secure_password"
python crypto_toolkit.py symmetric-decrypt --algorithm aes --input <encrypted_text> --password "secure_password"
```

### Asymmetric Encryption

```bash
# Generate key pair
python crypto_toolkit.py generate-keypair --output keys/

# Encrypt with public key
python crypto_toolkit.py asymmetric-encrypt --key keys/public_key.pem --input "Secret message"

# Decrypt with private key
python crypto_toolkit.py asymmetric-decrypt --key keys/private_key.pem --input <encrypted_text>
```

### Digital Signatures

```bash
# Sign a message
python crypto_toolkit.py sign --key keys/private_key.pem --input "Message to sign"

# Verify a signature
python crypto_toolkit.py verify --key keys/public_key.pem --input "Message to sign" --signature <signature>
```

### File Encryption

```bash
# Encrypt a file
python crypto_toolkit.py encrypt-file --input file.txt --output file.enc --password "secure_password"

# Decrypt a file
python crypto_toolkit.py decrypt-file --input file.enc --output file.txt --password "secure_password"
```

## Testing

The project includes a comprehensive test suite located in the `test/` directory. To run all tests:

```bash
cd test
./make_executable.sh  # Make all test scripts executable
./test_all.sh         # Run all tests
```

You can also run individual tests for specific components:

```bash
cd test
./test_symmetric.sh
./test_asymmetric.sh
# ... etc.
```

See the [test/README.md](test/README.md) file for more information about testing.

## Security Notes

This toolkit is meant for educational purposes to demonstrate cryptographic concepts. For production systems, consider using established libraries and frameworks with proper security auditing. 