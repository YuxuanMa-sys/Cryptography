#!/bin/bash
# Test script for secure messaging functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing Secure Messaging System${NC}"

# Create test users
USER1="alice_$$"
USER2="bob_$$"
MESSAGE="Hello Bob! This is a secret message from Alice."

# Setup secure messaging keys
echo -e "\n${YELLOW}Setting up encryption keys:${NC}"
python3 secure_messaging.py --setup

# Check if keys exist
if [ ! -d "keys" ] || [ ! -f "keys/public_key.pem" ] || [ ! -f "keys/private_key.pem" ]; then
    echo -e "${RED}✗ Key setup failed! Keys not found.${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Keys set up successfully.${NC}"
fi

# Send message from user1 to user2
echo -e "\n${YELLOW}Sending message from $USER1 to $USER2:${NC}"
python3 secure_messaging.py -u "$USER1" send --to "$USER2" --message "$MESSAGE"

# Check if message was sent (look for confirmation in output)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Message sent successfully.${NC}"
else
    echo -e "${RED}✗ Message sending failed!${NC}"
    exit 1
fi

# Read messages for user2 (providing empty input to skip reading message details)
echo -e "\n${YELLOW}Reading messages for $USER2:${NC}"
# Echo an empty line to handle the "Enter message number" prompt 
OUTPUT=$(echo "" | python3 secure_messaging.py -u "$USER2" read)
echo "$OUTPUT"

# Check if the message was listed in the table
if echo "$OUTPUT" | grep -q "$USER1"; then
    echo -e "${GREEN}✓ Message from $USER1 received successfully by $USER2!${NC}"
else
    echo -e "${RED}✗ Message receiving failed or sender not found!${NC}"
fi

echo -e "\n${GREEN}Secure messaging tests complete.${NC}" 