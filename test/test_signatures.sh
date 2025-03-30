#!/bin/bash
# Test script for digital signature functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing Digital Signature Functions${NC}"

# Create temporary directory for test keys
TEST_DIR="test_keys_$$"
mkdir -p "$TEST_DIR"

# Test message
MESSAGE="This message needs to be signed for authenticity verification"
SIGNATURE_FILE="$TEST_DIR/signature.b64"
MESSAGE_FILE="$TEST_DIR/message.txt"

# Write message to file
echo -n "$MESSAGE" > "$MESSAGE_FILE"

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

# Sign message and output to file
echo -e "\n${YELLOW}Testing Signature Generation:${NC}"
python3 crypto_toolkit.py sign --key "$TEST_DIR/private_key.pem" --input "$MESSAGE" --output "$SIGNATURE_FILE"

# Check if signature file was created
if [ ! -f "$SIGNATURE_FILE" ]; then
    echo -e "${RED}✗ Signature generation failed! Output file not created.${NC}"
    rm -rf "$TEST_DIR"
    exit 1
else
    # Read the signature from file
    SIGNATURE=$(cat "$SIGNATURE_FILE")
    echo -e "Generated signature: ${SIGNATURE:0:50}... (truncated)"
    echo -e "${GREEN}✓ Signature generated successfully.${NC}"
fi

# Verify valid signature
echo -e "\n${YELLOW}Testing Valid Signature Verification:${NC}"
RESULT=$(python3 crypto_toolkit.py verify --key "$TEST_DIR/public_key.pem" --input "$MESSAGE" --signature "$SIGNATURE")

# Extract verification result (clean up formatting)
VERIFICATION=$(echo "$RESULT" | grep "verification:" | awk '{print $NF}')
echo -e "Verification result: $VERIFICATION"

if [ "$VERIFICATION" = "VALID" ]; then
    echo -e "${GREEN}✓ Valid signature verification passed!${NC}"
else
    echo -e "${RED}✗ Valid signature verification failed!${NC}"
    # For debugging, show the full output
    echo -e "${YELLOW}Full verification output:${NC}"
    echo "$RESULT"
fi

# Verify invalid signature (tampered message)
echo -e "\n${YELLOW}Testing Invalid Signature Verification (tampered message):${NC}"
TAMPERED_MESSAGE="$MESSAGE - tampered"
RESULT=$(python3 crypto_toolkit.py verify --key "$TEST_DIR/public_key.pem" --input "$TAMPERED_MESSAGE" --signature "$SIGNATURE")

# Extract verification result (clean up formatting)
VERIFICATION=$(echo "$RESULT" | grep "verification:" | awk '{print $NF}')
echo -e "Verification result: $VERIFICATION"

if [ "$VERIFICATION" = "INVALID" ]; then
    echo -e "${GREEN}✓ Invalid signature detection passed!${NC}"
else
    echo -e "${RED}✗ Invalid signature detection failed!${NC}"
    # For debugging, show the full output
    echo -e "${YELLOW}Full verification output:${NC}"
    echo "$RESULT"
fi

# Clean up
echo -e "\n${YELLOW}Cleaning up test files...${NC}"
rm -rf "$TEST_DIR"

echo -e "\n${GREEN}Digital signature tests complete.${NC}" 