#!/bin/bash
# Test script for symmetric encryption functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing Symmetric Encryption Functions${NC}"

# Test message
MESSAGE="This is a secret message that needs encryption"
PASSWORD="test_password_123"

# Create temp files
TEMP_DIR=$(mktemp -d)
MESSAGE_FILE="$TEMP_DIR/message.txt"
ENCRYPTED_FILE_AES="$TEMP_DIR/encrypted_aes.json"
ENCRYPTED_FILE_CHACHA="$TEMP_DIR/encrypted_chacha.json"
DECRYPTED_FILE_AES="$TEMP_DIR/decrypted_aes.txt"
DECRYPTED_FILE_CHACHA="$TEMP_DIR/decrypted_chacha.txt"

# Write message to file
echo -n "$MESSAGE" > "$MESSAGE_FILE"

# Test AES encryption/decryption
echo -e "\n${YELLOW}Testing AES Encryption & Decryption:${NC}"

# Encrypt with AES (to file output)
python3 crypto_toolkit.py symmetric-encrypt --algorithm aes --input "$MESSAGE" --password "$PASSWORD" --output "$ENCRYPTED_FILE_AES"

# Verify encrypted file exists
if [ ! -f "$ENCRYPTED_FILE_AES" ]; then
    echo -e "${RED}✗ AES encryption failed - output file not created${NC}"
    exit 1
else
    echo -e "${GREEN}✓ AES encryption completed, output saved to file${NC}"
fi

# Use a simpler approach for decryption - run the command and extract content with sed
DECRYPTION_OUTPUT_AES=$(python3 crypto_toolkit.py symmetric-decrypt --algorithm aes --input "$ENCRYPTED_FILE_AES" --password "$PASSWORD")

# Extract just the actual message (between the panels)
# Important: Only remove the border characters, keep the spaces!
DECRYPTED=$(echo "$DECRYPTION_OUTPUT_AES" | sed -n '/Decrypted Data/,/^╰/p' | grep -v "Decrypted Data" | grep -v "^╭" | grep -v "^╰" | tr -d '│')
DECRYPTED=$(echo "$DECRYPTED" | sed 's/^[ \t]*//;s/[ \t]*$//')  # Trim both leading and trailing whitespace

echo -e "Original: '$MESSAGE'"
echo -e "Decrypted: '$DECRYPTED'"

if [ "$DECRYPTED" = "$MESSAGE" ]; then
    echo -e "${GREEN}✓ AES Test Passed!${NC}"
else
    echo -e "${RED}✗ AES Test Failed! Decrypted text doesn't match original.${NC}"
    # For debugging - look at what we got
    echo -e "${YELLOW}Full decryption output:${NC}"
    echo "$DECRYPTION_OUTPUT_AES" 
fi

# Test ChaCha20 encryption/decryption
echo -e "\n${YELLOW}Testing ChaCha20 Encryption & Decryption:${NC}"

# Encrypt with ChaCha20 (to file output)
python3 crypto_toolkit.py symmetric-encrypt --algorithm chacha20 --input "$MESSAGE" --password "$PASSWORD" --output "$ENCRYPTED_FILE_CHACHA"

# Verify encrypted file exists
if [ ! -f "$ENCRYPTED_FILE_CHACHA" ]; then
    echo -e "${RED}✗ ChaCha20 encryption failed - output file not created${NC}"
    exit 1
else
    echo -e "${GREEN}✓ ChaCha20 encryption completed, output saved to file${NC}"
fi

# Decrypt ChaCha20 using direct command
DECRYPTION_OUTPUT_CHACHA=$(python3 crypto_toolkit.py symmetric-decrypt --algorithm chacha20 --input "$ENCRYPTED_FILE_CHACHA" --password "$PASSWORD")

# Extract just the actual message
# Important: Only remove the border characters, keep the spaces!
DECRYPTED=$(echo "$DECRYPTION_OUTPUT_CHACHA" | sed -n '/Decrypted Data/,/^╰/p' | grep -v "Decrypted Data" | grep -v "^╭" | grep -v "^╰" | tr -d '│')
DECRYPTED=$(echo "$DECRYPTED" | sed 's/^[ \t]*//;s/[ \t]*$//')  # Trim both leading and trailing whitespace

echo -e "Original: '$MESSAGE'"
echo -e "Decrypted: '$DECRYPTED'"

if [ "$DECRYPTED" = "$MESSAGE" ]; then
    echo -e "${GREEN}✓ ChaCha20 Test Passed!${NC}"
else
    echo -e "${RED}✗ ChaCha20 Test Failed! Decrypted text doesn't match original.${NC}"
    # For debugging - look at what we got
    echo -e "${YELLOW}Full decryption output:${NC}"
    echo "$DECRYPTION_OUTPUT_CHACHA"
fi

# Clean up
rm -rf "$TEMP_DIR"

echo -e "\n${GREEN}Symmetric encryption tests complete.${NC}" 