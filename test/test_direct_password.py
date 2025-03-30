#!/usr/bin/env python3
"""
Direct test of password hashing functions bypassing shell formatting issues
"""
import os
import sys

# Add parent directory to Python path to import crypto_toolkit
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_toolkit import PasswordHashing

def test_password_hashing():
    """Test password hashing functions directly."""
    print("Testing Password Hashing Functions Directly")
    print("==========================================")
    
    # Test password
    password = "SecureP@ssw0rd123!"
    print(f"Test password: {password}")
    
    # Create hasher
    hasher = PasswordHashing()
    
    # Hash the password
    print("\nGenerating password hash...")
    try:
        hash_value = hasher.hash_password(password)
        print(f"Generated hash: {hash_value}")
        print("✓ Password hash generated successfully.")
    except Exception as e:
        print(f"✗ Password hashing failed: {str(e)}")
        return False
    
    # Verify correct password
    print("\nVerifying correct password...")
    try:
        result = hasher.verify_password(hash_value, password)
        print(f"Verification result: {result}")
        if result:
            print("✓ Correct password verification passed!")
        else:
            print("✗ Correct password verification failed!")
            return False
    except Exception as e:
        print(f"✗ Verification error: {str(e)}")
        return False
    
    # Verify incorrect password
    print("\nTesting incorrect password rejection...")
    wrong_password = "WrongP@ssw0rd"
    try:
        result = hasher.verify_password(hash_value, wrong_password)
        print(f"Verification result: {result}")
        if not result:
            print("✓ Incorrect password rejection passed!")
        else:
            print("✗ Incorrect password rejection failed!")
            return False
    except Exception as e:
        print(f"✗ Verification error: {str(e)}")
        return False
    
    print("\nAll password hashing tests passed!")
    return True

if __name__ == "__main__":
    success = test_password_hashing()
    sys.exit(0 if success else 1) 