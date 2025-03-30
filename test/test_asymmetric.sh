#!/bin/bash
# Test script for asymmetric encryption functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing Asymmetric Encryption Functions${NC}"

# Create temporary directory for test keys
TEST_DIR="test_keys_$$"
mkdir -p "$TEST_DIR"

# Test message
MESSAGE="This is a secret message for asymmetric encryption"

# Generate key pair
echo -e "\n${YELLOW}Generating RSA key pair:${NC}"
python3 crypto_toolkit.py generate-keypair --output "$TEST_DIR" --bits 2048

if [ ! -f "$TEST_DIR/public_key.pem" ] || [ ! -f "$TEST_DIR/private_key.pem" ]; then
    echo -e "${RED}✗ Key generation failed! Keys not found.${NC}"
    rm -rf "$TEST_DIR"
    exit 1
else
    echo -e "${GREEN}✓ Key pair generated successfully.${NC}"
fi

# Test encryption/decryption
echo -e "\n${YELLOW}Testing RSA Encryption & Decryption:${NC}"

# Create output file for encryption
ENCRYPTED_FILE="$TEST_DIR/encrypted.b64"

# Encrypt message to file
python3 crypto_toolkit.py asymmetric-encrypt --key "$TEST_DIR/public_key.pem" --input "$MESSAGE" --output "$ENCRYPTED_FILE"

# Check if encryption succeeded
if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo -e "${RED}✗ RSA encryption failed! Output file not created.${NC}"
    rm -rf "$TEST_DIR"
    exit 1
else
    echo -e "${GREEN}✓ Message encrypted successfully.${NC}"
    # Read encrypted data from file
    ENCRYPTED=$(cat "$ENCRYPTED_FILE")
    echo -e "Encrypted text (base64): ${ENCRYPTED:0:50}... (truncated)"
fi

# Decrypt the message
DECRYPTION_OUTPUT=$(python3 crypto_toolkit.py asymmetric-decrypt --key "$TEST_DIR/private_key.pem" --input "$ENCRYPTED")

# Extract just the actual message (between the panels)
DECRYPTED=$(echo "$DECRYPTION_OUTPUT" | sed -n '/Decrypted Data/,/^╰/p' | grep -v "Decrypted Data" | grep -v "^╭" | grep -v "^╰" | tr -d '│')
# Trim both leading and trailing whitespace
DECRYPTED=$(echo "$DECRYPTED" | sed 's/^[ \t]*//;s/[ \t]*$//')

echo -e "Original: '$MESSAGE'"
echo -e "Decrypted: '$DECRYPTED'"

if [ "$DECRYPTED" = "$MESSAGE" ]; then
    echo -e "${GREEN}✓ RSA Test Passed!${NC}"
else
    echo -e "${RED}✗ RSA Test Failed! Decrypted text doesn't match original.${NC}"
    echo -e "${YELLOW}Full decryption output:${NC}"
    echo "$DECRYPTION_OUTPUT"
fi

# Clean up
echo -e "\n${YELLOW}Cleaning up test files...${NC}"
rm -rf "$TEST_DIR"

echo -e "\n${GREEN}Asymmetric encryption tests complete.${NC}" 