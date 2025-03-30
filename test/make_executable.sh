#!/bin/bash
# Make all test scripts executable

# Get the directory of this script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Make all shell scripts executable
chmod +x test_*.sh

echo "All test scripts are now executable."
echo "Run ./test_all.sh to execute all tests, or run individual test scripts." 