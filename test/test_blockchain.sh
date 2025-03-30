#!/bin/bash
# Test script for blockchain functionality

# Colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set the base directory to the parent of the script's location
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo -e "${YELLOW}Testing Simple Blockchain Implementation${NC}"

# Test addresses
MINER="miner_$$"
SENDER="alice_$$"
RECIPIENT="bob_$$"
AMOUNT=5.0

# Backup existing blockchain file if it exists
if [ -f "blockchain.json" ]; then
    mv blockchain.json blockchain.json.bak
    echo -e "${YELLOW}Backed up existing blockchain.json${NC}"
fi

# Create a new blockchain
echo -e "\n${YELLOW}Creating a new blockchain:${NC}"
python3 simple_blockchain.py create
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ New blockchain created successfully${NC}"
else
    echo -e "${RED}✗ Failed to create new blockchain${NC}"
    # Restore backup if it exists
    if [ -f "blockchain.json.bak" ]; then
        mv blockchain.json.bak blockchain.json
    fi
    exit 1
fi

# Show the blockchain
echo -e "\n${YELLOW}Displaying the blockchain:${NC}"
python3 simple_blockchain.py show
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Blockchain displayed successfully${NC}"
else
    echo -e "${RED}✗ Failed to display blockchain${NC}"
    exit 1
fi

# Validate the empty blockchain
echo -e "\n${YELLOW}Validating the blockchain:${NC}"
VALIDATION_OUTPUT=$(python3 simple_blockchain.py validate)
echo "$VALIDATION_OUTPUT"
if echo "$VALIDATION_OUTPUT" | grep -q "Blockchain is valid"; then
    echo -e "${GREEN}✓ Initial blockchain validation passed${NC}"
else
    echo -e "${RED}✗ Initial blockchain validation failed${NC}"
    exit 1
fi

# Create a transaction
echo -e "\n${YELLOW}Creating a transaction:${NC}"
python3 simple_blockchain.py --address "$SENDER" transaction --to "$RECIPIENT" --amount $AMOUNT
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Transaction created successfully${NC}"
else
    echo -e "${RED}✗ Failed to create transaction${NC}"
    exit 1
fi

# Show pending transactions
echo -e "\n${YELLOW}Displaying pending transactions:${NC}"
PENDING_OUTPUT=$(python3 simple_blockchain.py show)
echo "$PENDING_OUTPUT"
if echo "$PENDING_OUTPUT" | grep -q "Pending Transactions"; then
    echo -e "${GREEN}✓ Pending transactions displayed successfully${NC}"
else
    echo -e "${RED}✗ No pending transactions displayed${NC}"
    exit 1
fi

# Mine the block
echo -e "\n${YELLOW}Mining a new block:${NC}"
# Temporarily redirect stderr to hide mining progress output
python3 simple_blockchain.py --address "$MINER" mine 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Block mined successfully${NC}"
else
    echo -e "${RED}✗ Failed to mine block${NC}"
    exit 1
fi

# Check recipient's balance
echo -e "\n${YELLOW}Checking recipient's balance:${NC}"
BALANCE_OUTPUT=$(python3 simple_blockchain.py balance --address "$RECIPIENT")
echo "$BALANCE_OUTPUT"
if echo "$BALANCE_OUTPUT" | grep -q "$AMOUNT"; then
    echo -e "${GREEN}✓ Recipient received the correct amount${NC}"
else
    echo -e "${RED}✗ Recipient balance check failed${NC}"
    exit 1
fi

# Check miner's balance
echo -e "\n${YELLOW}Checking miner's reward:${NC}"
MINER_OUTPUT=$(python3 simple_blockchain.py balance --address "$MINER")
echo "$MINER_OUTPUT"
if echo "$MINER_OUTPUT" | grep -q "Balance of $MINER"; then
    echo -e "${GREEN}✓ Miner received mining reward${NC}"
else
    echo -e "${RED}✗ Miner reward check failed${NC}"
    exit 1
fi

# Validate the blockchain again
echo -e "\n${YELLOW}Validating the blockchain after transactions:${NC}"
VALIDATION_OUTPUT=$(python3 simple_blockchain.py validate)
echo "$VALIDATION_OUTPUT"
if echo "$VALIDATION_OUTPUT" | grep -q "Blockchain is valid"; then
    echo -e "${GREEN}✓ Final blockchain validation passed${NC}"
else
    echo -e "${RED}✗ Final blockchain validation failed${NC}"
    exit 1
fi

# Clean up - restore original blockchain if a backup was made
if [ -f "blockchain.json.bak" ]; then
    mv blockchain.json.bak blockchain.json
    echo -e "${YELLOW}Restored original blockchain.json${NC}"
else
    # Remove test blockchain
    rm -f blockchain.json
    echo -e "${YELLOW}Removed test blockchain.json${NC}"
fi

echo -e "\n${GREEN}Blockchain tests completed successfully!${NC}" 