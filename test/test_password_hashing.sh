#!/bin/bash
# Test script for password hashing functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing Password Hashing Functions${NC}"

# Execute the direct Python test script
echo -e "\n${YELLOW}Running direct Python tests for password hashing...${NC}"
python3 test/test_direct_password.py

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Password hashing tests passed!${NC}"
else
    echo -e "${RED}✗ Password hashing tests failed!${NC}"
    exit 1
fi

echo -e "\n${GREEN}Password hashing tests complete.${NC}" 