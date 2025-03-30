# CryptoToolkit Test Suite

This directory contains comprehensive tests for all components of the CryptoToolkit.

## Test Scripts

The test suite includes the following test scripts:

- `test_all.sh` - Master script that runs all tests in sequence
- `test_symmetric.sh` - Tests symmetric encryption (AES, ChaCha20)
- `test_asymmetric.sh` - Tests asymmetric encryption (RSA)
- `test_signatures.sh` - Tests digital signature functionality
- `test_file_encryption.sh` - Tests file encryption/decryption
- `test_password_hashing.sh` - Tests password hashing and verification
- `test_direct_password.py` - Python script for direct password hashing tests
- `test_secure_messaging.sh` - Tests the secure messaging application
- `test_blockchain.sh` - Tests the simple blockchain implementation

## Running Tests

You can run individual test scripts or the complete test suite:

### Run All Tests

```bash
cd test
./test_all.sh
```

### Run Individual Tests

```bash
cd test
./test_symmetric.sh
./test_asymmetric.sh
./test_signatures.sh
./test_file_encryption.sh
./test_password_hashing.sh
./test_secure_messaging.sh
./test_blockchain.sh
```

## Test Results

Each test script will display its progress and results with colored output:
- Green ✓ indicates passed tests
- Red ✗ indicates failed tests
- Yellow text shows test descriptions and information

If any test fails, the script will exit with a non-zero status code and display diagnostic information to help troubleshoot the issue.

## Test Dependencies

All tests require the main CryptoToolkit modules to be properly installed. Make sure you have installed all dependencies from the main `requirements.txt` file before running the tests:

```bash
pip install -r requirements.txt
``` 