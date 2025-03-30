#!/usr/bin/env python3
"""
Secure Messaging Demo - Example application using CryptoToolkit
"""

import os
import json
import time
import getpass
import argparse
from pathlib import Path
from datetime import datetime

# Import cryptography classes from our toolkit
from crypto_toolkit import (
    AsymmetricEncryption, 
    SymmetricEncryption,
    DigitalSignature,
    PasswordHashing,
    encode_base64,
    decode_base64
)

# Rich for nice terminal output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Initialize console
console = Console()

def setup_keys(directory="keys"):
    """Setup encryption keys if they don't exist yet."""
    # Create directory if it doesn't exist
    Path(directory).mkdir(exist_ok=True)
    
    # Check if keys already exist
    private_key_path = Path(directory) / "private_key.pem"
    public_key_path = Path(directory) / "public_key.pem"
    
    if private_key_path.exists() and public_key_path.exists():
        console.print("[yellow]Keys already exist, using existing keys.[/yellow]")
        return
    
    # Generate new key pair
    console.print("[cyan]Generating new RSA key pair...[/cyan]")
    private_key, public_key = AsymmetricEncryption.generate_key_pair()
    
    # Save keys
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    
    with open(public_key_path, 'wb') as f:
        f.write(public_key)
    
    console.print(f"[green]Key pair generated successfully.[/green]")
    console.print(f"[green]Private key saved to: {private_key_path}[/green]")
    console.print(f"[green]Public key saved to: {public_key_path}[/green]")


def load_keys(directory="keys"):
    """Load keys from files."""
    private_key_path = Path(directory) / "private_key.pem"
    public_key_path = Path(directory) / "public_key.pem"
    
    if not private_key_path.exists() or not public_key_path.exists():
        console.print("[red]Keys not found. Please run setup first.[/red]")
        return None, None
    
    with open(private_key_path, 'rb') as f:
        private_key_data = f.read()
    
    with open(public_key_path, 'rb') as f:
        public_key_data = f.read()
    
    private_key = AsymmetricEncryption.load_private_key(private_key_data)
    public_key = AsymmetricEncryption.load_public_key(public_key_data)
    
    return private_key, public_key


class SecureMessage:
    """Class representing a secure message."""
    
    def __init__(self, sender, recipient, content, timestamp=None):
        self.sender = sender
        self.recipient = recipient
        self.content = content
        self.timestamp = timestamp or datetime.now().isoformat()
        self.signature = None
    
    def encrypt(self, recipient_public_key):
        """Encrypt the message for the recipient."""
        message_data = {
            "sender": self.sender,
            "recipient": self.recipient,
            "content": self.content,
            "timestamp": self.timestamp
        }
        
        # Serialize the message
        serialized = json.dumps(message_data)
        
        # Encrypt using recipient's public key
        encrypted = AsymmetricEncryption.encrypt_rsa(recipient_public_key, serialized)
        
        return encrypted
    
    def sign(self, private_key):
        """Sign the message with sender's private key."""
        message_data = {
            "sender": self.sender,
            "recipient": self.recipient,
            "content": self.content,
            "timestamp": self.timestamp
        }
        
        # Serialize the message
        serialized = json.dumps(message_data)
        
        # Sign the message
        self.signature = DigitalSignature.sign(private_key, serialized)
        
        return self.signature
    
    @staticmethod
    def decrypt(encrypted_message, private_key):
        """Decrypt a message using private key."""
        try:
            decrypted_json = AsymmetricEncryption.decrypt_rsa(private_key, encrypted_message)
            message_data = json.loads(decrypted_json)
            
            message = SecureMessage(
                sender=message_data["sender"],
                recipient=message_data["recipient"],
                content=message_data["content"],
                timestamp=message_data["timestamp"]
            )
            
            return message
        except Exception as e:
            console.print(f"[red]Failed to decrypt message: {str(e)}[/red]")
            return None
    
    @staticmethod
    def verify(message, signature, public_key):
        """Verify a message signature."""
        message_data = {
            "sender": message.sender,
            "recipient": message.recipient,
            "content": message.content,
            "timestamp": message.timestamp
        }
        
        # Serialize the message
        serialized = json.dumps(message_data)
        
        # Verify the signature
        return DigitalSignature.verify(public_key, serialized, signature)


class SecureMessagingSystem:
    """Secure messaging system using cryptography."""
    
    def __init__(self, username, keys_dir="keys"):
        self.username = username
        self.keys_dir = keys_dir
        self.messages_dir = Path("messages")
        self.messages_dir.mkdir(exist_ok=True)
        
        # Load keys
        self.private_key, self.public_key = load_keys(keys_dir)
        
        if not self.private_key or not self.public_key:
            setup_keys(keys_dir)
            self.private_key, self.public_key = load_keys(keys_dir)
    
    def send_message(self, recipient, content):
        """Send a secure message to recipient."""
        # Create a message
        message = SecureMessage(
            sender=self.username,
            recipient=recipient,
            content=content
        )
        
        # Sign the message
        signature = message.sign(self.private_key)
        
        # For demo purposes, we'll use our own public key for encryption
        # In a real system, you would look up the recipient's public key
        encrypted = message.encrypt(self.public_key)
        
        # Save the message
        message_file = self.messages_dir / f"{int(time.time())}.msg"
        with open(message_file, 'w') as f:
            f.write(json.dumps({
                "encrypted": encrypted,
                "signature": signature,
                "sender": self.username,
                "recipient": recipient,
                "timestamp": message.timestamp
            }))
        
        console.print(f"[green]Message sent and saved to {message_file}[/green]")
    
    def read_messages(self):
        """Read all messages in the inbox."""
        messages = []
        
        for file in self.messages_dir.glob("*.msg"):
            with open(file, 'r') as f:
                data = json.loads(f.read())
            
            if data.get("recipient") == self.username:
                messages.append((file, data))
        
        if not messages:
            console.print("[yellow]No messages found for you.[/yellow]")
            return
        
        # Display messages in a table
        table = Table(title=f"Messages for {self.username}")
        table.add_column("ID", style="cyan")
        table.add_column("From", style="magenta")
        table.add_column("Date", style="green")
        table.add_column("Status", style="yellow")
        
        for i, (file, data) in enumerate(messages):
            timestamp = data.get("timestamp", "Unknown")
            sender = data.get("sender", "Unknown")
            
            # Try to decrypt
            try:
                encrypted = data.get("encrypted")
                signature = data.get("signature")
                
                decrypted = SecureMessage.decrypt(encrypted, self.private_key)
                verified = SecureMessage.verify(decrypted, signature, self.public_key)
                
                status = "[green]Verified[/green]" if verified else "[red]Unverified[/red]"
            except Exception:
                status = "[red]Decrypt Failed[/red]"
            
            table.add_row(str(i+1), sender, timestamp, status)
        
        console.print(table)
        
        # Ask which message to read
        choice = console.input("[cyan]Enter message number to read (or ENTER to cancel): [/cyan]")
        if not choice:
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(messages):
                file, data = messages[idx]
                
                encrypted = data.get("encrypted")
                signature = data.get("signature")
                
                decrypted = SecureMessage.decrypt(encrypted, self.private_key)
                verified = SecureMessage.verify(decrypted, signature, self.public_key)
                
                # Show message
                panel = Panel.fit(
                    f"From: {decrypted.sender}\n"
                    f"To: {decrypted.recipient}\n"
                    f"Date: {decrypted.timestamp}\n"
                    f"Signature: {'VERIFIED' if verified else 'INVALID'}\n"
                    f"\n{decrypted.content}",
                    title=f"Message {idx+1}",
                    border_style="green" if verified else "red"
                )
                console.print(panel)
            else:
                console.print("[red]Invalid message number.[/red]")
        except Exception as e:
            console.print(f"[red]Error reading message: {str(e)}[/red]")


def main():
    parser = argparse.ArgumentParser(description="Secure Messaging Demo")
    parser.add_argument("--username", "-u", default=os.getlogin(), help="Your username")
    parser.add_argument("--setup", action="store_true", help="Setup encryption keys")
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Send command
    send_parser = subparsers.add_parser("send", help="Send a message")
    send_parser.add_argument("--to", "-t", required=True, help="Recipient username")
    send_parser.add_argument("--message", "-m", help="Message content")
    
    # Read command
    read_parser = subparsers.add_parser("read", help="Read messages")
    
    args = parser.parse_args()
    
    # Display a header
    console.print(Panel.fit(
        "[bold]Secure Messaging Demo[/bold]\nUsing CryptoToolkit for end-to-end encryption",
        border_style="cyan"
    ))
    
    if args.setup:
        setup_keys()
        return
    
    messaging = SecureMessagingSystem(args.username)
    
    if args.command == "send":
        message = args.message
        if not message:
            message = console.input("[cyan]Enter your message: [/cyan]")
        
        messaging.send_message(args.to, message)
    
    elif args.command == "read":
        messaging.read_messages()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 