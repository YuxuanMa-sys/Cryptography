#!/bin/bash
# Test script for file encryption/decryption functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing File Encryption Functions${NC}"

# Create a test file
TEST_FILE="test_file_$$.txt"
ENCRYPTED_FILE="$TEST_FILE.enc"
DECRYPTED_FILE="decrypted_$TEST_FILE"
PASSWORD="test_file_password_123"

# Create file with test content
echo -e "\n${YELLOW}Creating test file:${NC}"
cat > "$TEST_FILE" << EOF
This is a sample file with content that needs to be encrypted.
It contains multiple lines and some sensitive information:
- Credit Card: 1234-5678-9012-3456
- Password: supersecretpassword
- Secret Key: a1b2c3d4e5f6g7h8

This file should be secured with encryption!
EOF

echo -e "Created test file: $TEST_FILE"

# Encrypt the file
echo -e "\n${YELLOW}Testing File Encryption:${NC}"
python3 crypto_toolkit.py encrypt-file --input "$TEST_FILE" --output "$ENCRYPTED_FILE" --password "$PASSWORD"

if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo -e "${RED}✗ File encryption failed! Encrypted file not found.${NC}"
    rm -f "$TEST_FILE"
    exit 1
else
    echo -e "${GREEN}✓ File encrypted successfully.${NC}"
    echo -e "Original file size: $(du -h "$TEST_FILE" | cut -f1)"
    echo -e "Encrypted file size: $(du -h "$ENCRYPTED_FILE" | cut -f1)"
fi

# Decrypt the file
echo -e "\n${YELLOW}Testing File Decryption:${NC}"
python3 crypto_toolkit.py decrypt-file --input "$ENCRYPTED_FILE" --output "$DECRYPTED_FILE" --password "$PASSWORD"

if [ ! -f "$DECRYPTED_FILE" ]; then
    echo -e "${RED}✗ File decryption failed! Decrypted file not found.${NC}"
    rm -f "$TEST_FILE" "$ENCRYPTED_FILE"
    exit 1
else
    echo -e "${GREEN}✓ File decrypted successfully.${NC}"
fi

# Compare original and decrypted files
echo -e "\n${YELLOW}Comparing original and decrypted files:${NC}"
if cmp -s "$TEST_FILE" "$DECRYPTED_FILE"; then
    echo -e "${GREEN}✓ Files match! Encryption/decryption process worked correctly.${NC}"
else
    echo -e "${RED}✗ Files don't match! Encryption/decryption process failed.${NC}"
    diff "$TEST_FILE" "$DECRYPTED_FILE"
fi

# Clean up
echo -e "\n${YELLOW}Cleaning up test files...${NC}"
rm -f "$TEST_FILE" "$ENCRYPTED_FILE" "$DECRYPTED_FILE"

echo -e "\n${GREEN}File encryption tests complete.${NC}" 