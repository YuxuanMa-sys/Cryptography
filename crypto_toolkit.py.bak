#!/usr/bin/env python3
"""
CryptoToolkit - A comprehensive cryptography toolkit demonstrating various encryption techniques
"""

import argparse
import base64
import getpass
import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union

# Cryptography libraries
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# Argon2 for secure password hashing
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Rich for nice terminal output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

# Initialize console
console = Console()


# === Utility Functions ===

def generate_salt(size: int = 16) -> bytes:
    """Generate a random salt of specified size."""
    return os.urandom(size)


def derive_key_from_password(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """Derive a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode('utf-8')


def decode_base64(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data.encode('utf-8'))


# === Symmetric Encryption ===

class SymmetricEncryption:
    """Class handling symmetric encryption operations."""

    @staticmethod
    def encrypt_aes(plaintext: str, password: str) -> Dict[str, str]:
        """Encrypt data using AES-256-GCM."""
        salt = generate_salt(16)
        key = derive_key_from_password(password, salt, 32)
        iv = os.urandom(12)  # GCM mode requires 12 bytes IV
        
        # Create an encryptor
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        ).encryptor()
        
        # Convert plaintext to bytes and encrypt
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # Return the encrypted data with necessary parameters for decryption
        return {
            "algorithm": "AES-256-GCM",
            "ciphertext": encode_base64(ciphertext),
            "iv": encode_base64(iv),
            "salt": encode_base64(salt),
            "tag": encode_base64(encryptor.tag)
        }
    
    @staticmethod
    def decrypt_aes(encrypted_data: Dict[str, str], password: str) -> str:
        """Decrypt AES-256-GCM encrypted data."""
        # Extract parameters
        ciphertext = decode_base64(encrypted_data["ciphertext"])
        iv = decode_base64(encrypted_data["iv"])
        salt = decode_base64(encrypted_data["salt"])
        tag = decode_base64(encrypted_data["tag"])
        
        # Derive the same key from password and salt
        key = derive_key_from_password(password, salt, 32)
        
        # Create a decryptor with the tag
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        # Decrypt and return
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt_chacha20(plaintext: str, password: str) -> Dict[str, str]:
        """Encrypt data using ChaCha20-Poly1305."""
        salt = generate_salt(16)
        key = derive_key_from_password(password, salt, 32)
        nonce = os.urandom(12)  # ChaCha20 requires 12 bytes nonce (not 24)
        
        # For simplicity, using equivalent from cryptography library
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext.encode(), None)
        
        return {
            "algorithm": "ChaCha20-Poly1305",
            "ciphertext": encode_base64(ciphertext),
            "nonce": encode_base64(nonce),
            "salt": encode_base64(salt)
        }
    
    @staticmethod
    def decrypt_chacha20(encrypted_data: Dict[str, str], password: str) -> str:
        """Decrypt ChaCha20-Poly1305 encrypted data."""
        # Extract parameters
        ciphertext = decode_base64(encrypted_data["ciphertext"])
        nonce = decode_base64(encrypted_data["nonce"])
        salt = decode_base64(encrypted_data["salt"])
        
        # Derive the same key from password and salt
        key = derive_key_from_password(password, salt, 32)
        
        # Decrypt using ChaCha20Poly1305
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode('utf-8')


# === Asymmetric Encryption ===

class AsymmetricEncryption:
    """Class handling asymmetric encryption operations."""
    
    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """Generate an RSA key pair."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Get public key from private key
        public_key = private_key.public_key()
        
        # Serialize private key to PEM format (no encryption for demo)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def load_public_key(key_data: bytes) -> rsa.RSAPublicKey:
        """Load a public key from PEM-encoded data."""
        return serialization.load_pem_public_key(key_data)
    
    @staticmethod
    def load_private_key(key_data: bytes) -> rsa.RSAPrivateKey:
        """Load a private key from PEM-encoded data."""
        return serialization.load_pem_private_key(key_data, password=None)
    
    @staticmethod
    def encrypt_rsa(public_key: rsa.RSAPublicKey, plaintext: str) -> str:
        """Encrypt data using RSA public key."""
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encode_base64(ciphertext)
    
    @staticmethod
    def decrypt_rsa(private_key: rsa.RSAPrivateKey, ciphertext: str) -> str:
        """Decrypt data using RSA private key."""
        plaintext = private_key.decrypt(
            decode_base64(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')


# === Digital Signatures ===

class DigitalSignature:
    """Class handling digital signature operations."""
    
    @staticmethod
    def sign(private_key: rsa.RSAPrivateKey, message: str) -> str:
        """Sign a message using a private key."""
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return encode_base64(signature)
    
    @staticmethod
    def verify(public_key: rsa.RSAPublicKey, message: str, signature: str) -> bool:
        """Verify a signature using a public key."""
        try:
            public_key.verify(
                decode_base64(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


# === File Operations ===

class FileOperations:
    """Class handling file encryption and decryption."""
    
    @staticmethod
    def encrypt_file(input_file: str, output_file: str, password: str) -> None:
        """Encrypt a file using AES-256-GCM."""
        # Read the input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        # Generate salt and derive key
        salt = generate_salt(16)
        key = derive_key_from_password(password, salt, 32)
        iv = os.urandom(12)
        
        # Create an encryptor
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        ).encryptor()
        
        # Encrypt the file contents
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Write the encrypted data to the output file
        # Format: salt + iv + tag_length + tag + ciphertext
        with open(output_file, 'wb') as f:
            f.write(salt)
            f.write(iv)
            tag = encryptor.tag
            f.write(len(tag).to_bytes(1, byteorder='big'))
            f.write(tag)
            f.write(ciphertext)
    
    @staticmethod
    def decrypt_file(input_file: str, output_file: str, password: str) -> None:
        """Decrypt a file encrypted with AES-256-GCM."""
        # Read the encrypted file
        with open(input_file, 'rb') as f:
            # Extract parameters
            salt = f.read(16)
            iv = f.read(12)
            tag_length = int.from_bytes(f.read(1), byteorder='big')
            tag = f.read(tag_length)
            ciphertext = f.read()
        
        # Derive the key
        key = derive_key_from_password(password, salt, 32)
        
        # Create a decryptor
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        # Decrypt the file contents
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Write the decrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)


# === Password Hashing ===

class PasswordHashing:
    """Class handling secure password hashing and verification."""
    
    def __init__(self):
        """Initialize with default parameters."""
        self.hasher = PasswordHasher(
            time_cost=2,      # Number of iterations
            memory_cost=65536,  # Memory usage
            parallelism=4,    # Number of parallel threads
            hash_len=32,      # Length of the hash in bytes
            salt_len=16       # Length of the salt in bytes
        )
    
    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2."""
        return self.hasher.hash(password)
    
    def verify_password(self, hash_str: str, password: str) -> bool:
        """Verify a password against its hash."""
        try:
            self.hasher.verify(hash_str, password)
            return True
        except VerifyMismatchError:
            return False


# === Command Line Interface ===

def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(description="CryptoToolkit - A comprehensive cryptography toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Symmetric encryption commands
    sym_encrypt = subparsers.add_parser("symmetric-encrypt", help="Encrypt data using symmetric encryption")
    sym_encrypt.add_argument("--algorithm", choices=["aes", "chacha20"], default="aes", help="Encryption algorithm")
    sym_encrypt.add_argument("--input", required=True, help="Input text to encrypt")
    sym_encrypt.add_argument("--password", help="Encryption password (will prompt if not provided)")
    sym_encrypt.add_argument("--output", help="Output file for encrypted data (prints to console if not provided)")
    
    sym_decrypt = subparsers.add_parser("symmetric-decrypt", help="Decrypt symmetrically encrypted data")
    sym_decrypt.add_argument("--algorithm", choices=["aes", "chacha20"], default="aes", help="Decryption algorithm")
    sym_decrypt.add_argument("--input", required=True, help="Input text or file containing encrypted data")
    sym_decrypt.add_argument("--password", help="Decryption password (will prompt if not provided)")
    
    # Asymmetric encryption commands
    gen_keypair = subparsers.add_parser("generate-keypair", help="Generate RSA key pair")
    gen_keypair.add_argument("--bits", type=int, default=2048, help="Key size in bits")
    gen_keypair.add_argument("--output", default=".", help="Directory to store keys")
    
    asym_encrypt = subparsers.add_parser("asymmetric-encrypt", help="Encrypt data using RSA")
    asym_encrypt.add_argument("--key", required=True, help="Path to public key file")
    asym_encrypt.add_argument("--input", required=True, help="Input text to encrypt")
    asym_encrypt.add_argument("--output", help="Output file for encrypted data")
    
    asym_decrypt = subparsers.add_parser("asymmetric-decrypt", help="Decrypt RSA encrypted data")
    asym_decrypt.add_argument("--key", required=True, help="Path to private key file")
    asym_decrypt.add_argument("--input", required=True, help="Encrypted text or file path")
    
    # Digital signature commands
    sign = subparsers.add_parser("sign", help="Sign a message")
    sign.add_argument("--key", required=True, help="Path to private key file")
    sign.add_argument("--input", required=True, help="Input text or file to sign")
    sign.add_argument("--output", help="Output file for signature")
    
    verify = subparsers.add_parser("verify", help="Verify a signature")
    verify.add_argument("--key", required=True, help="Path to public key file")
    verify.add_argument("--input", required=True, help="Input text or file that was signed")
    verify.add_argument("--signature", required=True, help="Signature to verify")
    
    # File encryption commands
    file_encrypt = subparsers.add_parser("encrypt-file", help="Encrypt a file")
    file_encrypt.add_argument("--input", required=True, help="Input file to encrypt")
    file_encrypt.add_argument("--output", help="Output encrypted file (default: input.enc)")
    file_encrypt.add_argument("--password", help="Encryption password (will prompt if not provided)")
    
    file_decrypt = subparsers.add_parser("decrypt-file", help="Decrypt a file")
    file_decrypt.add_argument("--input", required=True, help="Input encrypted file")
    file_decrypt.add_argument("--output", help="Output decrypted file (default: input without .enc)")
    file_decrypt.add_argument("--password", help="Decryption password (will prompt if not provided)")
    
    # Password hashing commands
    hash_pwd = subparsers.add_parser("hash-password", help="Hash a password")
    hash_pwd.add_argument("--password", help="Password to hash (will prompt if not provided)")
    
    verify_pwd = subparsers.add_parser("verify-password", help="Verify a password against its hash")
    verify_pwd.add_argument("--hash", required=True, help="Hash to verify against")
    verify_pwd.add_argument("--password", help="Password to verify (will prompt if not provided)")
    
    return parser


def handle_symmetric_encrypt(args):
    """Handle symmetric encryption command."""
    password = args.password or getpass.getpass("Enter encryption password: ")
    
    if args.algorithm == "aes":
        encrypted = SymmetricEncryption.encrypt_aes(args.input, password)
    else:  # chacha20
        encrypted = SymmetricEncryption.encrypt_chacha20(args.input, password)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(json.dumps(encrypted, indent=2))
        console.print(f"[green]Encrypted data saved to {args.output}[/green]")
    else:
        console.print(Panel.fit(
            json.dumps(encrypted, indent=2),
            title="Encrypted Data",
            border_style="green"
        ))


def handle_symmetric_decrypt(args):
    """Handle symmetric decryption command."""
    password = args.password or getpass.getpass("Enter decryption password: ")
    
    # Check if input is a file or direct string
    if os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            encrypted_data = json.loads(f.read())
    else:
        try:
            encrypted_data = json.loads(args.input)
        except json.JSONDecodeError:
            console.print("[red]Error: Input is not a valid JSON string or file[/red]")
            return
    
    try:
        if args.algorithm == "aes" or encrypted_data.get("algorithm", "").startswith("AES"):
            decrypted = SymmetricEncryption.decrypt_aes(encrypted_data, password)
        else:  # chacha20
            decrypted = SymmetricEncryption.decrypt_chacha20(encrypted_data, password)
        
        console.print(Panel.fit(
            decrypted,
            title="Decrypted Data",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[red]Decryption failed: {str(e)}[/red]")


def handle_generate_keypair(args):
    """Handle key pair generation command."""
    private_key, public_key = AsymmetricEncryption.generate_key_pair(args.bits)
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True, parents=True)
    
    with open(output_dir / "private_key.pem", 'wb') as f:
        f.write(private_key)
    
    with open(output_dir / "public_key.pem", 'wb') as f:
        f.write(public_key)
    
    console.print(f"[green]Key pair generated:[/green]")
    console.print(f"[green]Private key saved to: {output_dir / 'private_key.pem'}[/green]")
    console.print(f"[green]Public key saved to: {output_dir / 'public_key.pem'}[/green]")
    console.print("[yellow]Warning: Keep your private key secure![/yellow]")


def handle_asymmetric_encrypt(args):
    """Handle asymmetric encryption command."""
    with open(args.key, 'rb') as f:
        public_key_data = f.read()
    
    public_key = AsymmetricEncryption.load_public_key(public_key_data)
    encrypted = AsymmetricEncryption.encrypt_rsa(public_key, args.input)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(encrypted)
        console.print(f"[green]Encrypted data saved to {args.output}[/green]")
    else:
        console.print(Panel.fit(
            encrypted,
            title="Encrypted Data (Base64)",
            border_style="green"
        ))


def handle_asymmetric_decrypt(args):
    """Handle asymmetric decryption command."""
    with open(args.key, 'rb') as f:
        private_key_data = f.read()
    
    private_key = AsymmetricEncryption.load_private_key(private_key_data)
    
    # Check if input is a file or direct string
    if os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            ciphertext = f.read().strip()
    else:
        ciphertext = args.input
    
    try:
        decrypted = AsymmetricEncryption.decrypt_rsa(private_key, ciphertext)
        console.print(Panel.fit(
            decrypted,
            title="Decrypted Data",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[red]Decryption failed: {str(e)}[/red]")


def handle_sign(args):
    """Handle digital signature command."""
    with open(args.key, 'rb') as f:
        private_key_data = f.read()
    
    private_key = AsymmetricEncryption.load_private_key(private_key_data)
    
    # Check if input is a file
    if os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            message = f.read()
    else:
        message = args.input
    
    signature = DigitalSignature.sign(private_key, message)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(signature)
        console.print(f"[green]Signature saved to {args.output}[/green]")
    else:
        console.print(Panel.fit(
            signature,
            title="Digital Signature (Base64)",
            border_style="green"
        ))


def handle_verify(args):
    """Handle signature verification command."""
    with open(args.key, 'rb') as f:
        public_key_data = f.read()
    
    public_key = AsymmetricEncryption.load_public_key(public_key_data)
    
    # Check if input is a file
    if os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            message = f.read()
    else:
        message = args.input
    
    # Check if signature is a file
    if os.path.isfile(args.signature):
        with open(args.signature, 'r') as f:
            signature = f.read().strip()
    else:
        signature = args.signature
    
    verified = DigitalSignature.verify(public_key, message, signature)
    
    if verified:
        console.print("[green]Signature verification: VALID[/green]")
    else:
        console.print("[red]Signature verification: INVALID[/red]")


def handle_encrypt_file(args):
    """Handle file encryption command."""
    input_file = args.input
    output_file = args.output or f"{input_file}.enc"
    
    if not os.path.isfile(input_file):
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return
    
    password = args.password or getpass.getpass("Enter encryption password: ")
    
    try:
        FileOperations.encrypt_file(input_file, output_file, password)
        console.print(f"[green]File encrypted successfully. Output: {output_file}[/green]")
    except Exception as e:
        console.print(f"[red]File encryption failed: {str(e)}[/red]")


def handle_decrypt_file(args):
    """Handle file decryption command."""
    input_file = args.input
    
    if not os.path.isfile(input_file):
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return
    
    # Default output filename: remove .enc extension if present
    if not args.output:
        if input_file.endswith('.enc'):
            output_file = input_file[:-4]
        else:
            output_file = f"{input_file}.dec"
    else:
        output_file = args.output
    
    password = args.password or getpass.getpass("Enter decryption password: ")
    
    try:
        FileOperations.decrypt_file(input_file, output_file, password)
        console.print(f"[green]File decrypted successfully. Output: {output_file}[/green]")
    except Exception as e:
        console.print(f"[red]File decryption failed: {str(e)}[/red]")


def handle_hash_password(args):
    """Handle password hashing command."""
    password = args.password or getpass.getpass("Enter password to hash: ")
    
    hasher = PasswordHashing()
    hash_result = hasher.hash_password(password)
    
    console.print(Panel.fit(
        hash_result,
        title="Password Hash (Argon2)",
        border_style="green"
    ))


def handle_verify_password(args):
    """Handle password verification command."""
    password = args.password or getpass.getpass("Enter password to verify: ")
    
    hasher = PasswordHashing()
    verified = hasher.verify_password(args.hash, password)
    
    if verified:
        console.print("[green]Password verification: VALID[/green]")
    else:
        console.print("[red]Password verification: INVALID[/red]")


def main():
    """Main entry point for the application."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Display a header
    console.print(Panel.fit(
        "[bold]CryptoToolkit[/bold]\nA comprehensive cryptography toolkit",
        border_style="cyan"
    ))
    
    # Handle the command
    if args.command == "symmetric-encrypt":
        handle_symmetric_encrypt(args)
    elif args.command == "symmetric-decrypt":
        handle_symmetric_decrypt(args)
    elif args.command == "generate-keypair":
        handle_generate_keypair(args)
    elif args.command == "asymmetric-encrypt":
        handle_asymmetric_encrypt(args)
    elif args.command == "asymmetric-decrypt":
        handle_asymmetric_decrypt(args)
    elif args.command == "sign":
        handle_sign(args)
    elif args.command == "verify":
        handle_verify(args)
    elif args.command == "encrypt-file":
        handle_encrypt_file(args)
    elif args.command == "decrypt-file":
        handle_decrypt_file(args)
    elif args.command == "hash-password":
        handle_hash_password(args)
    elif args.command == "verify-password":
        handle_verify_password(args)


if __name__ == "__main__":
    main() 