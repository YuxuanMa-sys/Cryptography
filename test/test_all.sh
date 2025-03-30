#!/bin/bash
# Master test script for CryptoToolkit

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set the base directory to the script's location
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$TEST_DIR"

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}CryptoToolkit Comprehensive Test Suite${NC}"
echo -e "${BLUE}=======================================${NC}"

# Make all individual test scripts executable
chmod +x test_symmetric.sh test_asymmetric.sh test_signatures.sh test_file_encryption.sh test_password_hashing.sh test_secure_messaging.sh test_blockchain.sh

# Run individual test scripts
echo -e "\n${YELLOW}Running test 1/7: Symmetric Encryption${NC}"
./test_symmetric.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${YELLOW}Running test 2/7: Asymmetric Encryption${NC}"
./test_asymmetric.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${YELLOW}Running test 3/7: Digital Signatures${NC}"
./test_signatures.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${YELLOW}Running test 4/7: File Encryption${NC}"
./test_file_encryption.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${YELLOW}Running test 5/7: Password Hashing${NC}"
./test_password_hashing.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${YELLOW}Running test 6/7: Secure Messaging${NC}"
./test_secure_messaging.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${YELLOW}Running test 7/7: Blockchain${NC}"
./test_blockchain.sh
echo -e "\n${BLUE}=======================================${NC}"

echo -e "\n${GREEN}All tests completed.${NC}" 