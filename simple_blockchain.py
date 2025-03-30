#!/usr/bin/env python3
"""
Simple Blockchain Implementation - Demonstrating cryptographic concepts
"""

import json
import time
import hashlib
from pathlib import Path
import argparse
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import from our crypto toolkit
from crypto_toolkit import (
    AsymmetricEncryption,
    DigitalSignature,
    encode_base64,
    decode_base64
)

# Rich for nice terminal output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Initialize console
console = Console()


class Transaction:
    """Represents a transaction in the blockchain."""
    
    def __init__(self, sender: str, recipient: str, amount: float, timestamp: Optional[str] = None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp or datetime.now().isoformat()
        self.signature = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to dictionary."""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        """Create transaction from dictionary."""
        tx = cls(
            sender=data["sender"],
            recipient=data["recipient"],
            amount=data["amount"],
            timestamp=data["timestamp"]
        )
        tx.signature = data.get("signature")
        return tx
    
    def calculate_hash(self) -> str:
        """Calculate hash of the transaction."""
        # Create a string representation of the transaction without the signature
        tx_string = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def sign(self, private_key) -> None:
        """Sign the transaction."""
        # Create message string without signature
        tx_dict = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp
        }
        
        message = json.dumps(tx_dict, sort_keys=True)
        self.signature = DigitalSignature.sign(private_key, message)
    
    def verify_signature(self, public_key) -> bool:
        """Verify the transaction signature."""
        if not self.signature:
            return False
        
        # Recreate the message that was signed
        tx_dict = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp
        }
        
        message = json.dumps(tx_dict, sort_keys=True)
        return DigitalSignature.verify(public_key, message, self.signature)


class Block:
    """Represents a block in the blockchain."""
    
    def __init__(self, index: int, transactions: List[Transaction], 
                 previous_hash: str, timestamp: Optional[str] = None, 
                 nonce: int = 0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp or datetime.now().isoformat()
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate the hash of the block."""
        # Convert transactions to dict for hashing
        tx_dicts = [tx.to_dict() for tx in self.transactions]
        
        # Create a string representation of the block
        block_string = json.dumps({
            "index": self.index,
            "transactions": tx_dicts,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty: int) -> None:
        """Mine the block (find a hash with the required difficulty)."""
        # Create a target string with 'difficulty' leading zeros
        target = '0' * difficulty
        
        console.print(f"[cyan]Mining block {self.index}...[/cyan]")
        
        # Keep incrementing nonce until we find a hash with the required number of leading zeros
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
            
            # Print progress every 10000 attempts
            if self.nonce % 10000 == 0:
                console.print(f"[cyan]Nonce: {self.nonce}, Hash: {self.hash}[/cyan]")
        
        console.print(f"[green]Block mined! Hash: {self.hash}[/green]")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary."""
        return {
            "index": self.index,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create block from dictionary."""
        transactions = [Transaction.from_dict(tx) for tx in data["transactions"]]
        
        block = cls(
            index=data["index"],
            transactions=transactions,
            previous_hash=data["previous_hash"],
            timestamp=data["timestamp"],
            nonce=data["nonce"]
        )
        
        # Verify the hash
        calculated_hash = block.calculate_hash()
        if calculated_hash != data["hash"]:
            console.print(f"[yellow]Warning: Block {block.index} hash doesn't match calculated hash.[/yellow]")
            block.hash = calculated_hash
        else:
            block.hash = data["hash"]
        
        return block


class Blockchain:
    """Simple blockchain implementation."""
    
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.difficulty = difficulty
        self.mining_reward = 1.0
        
        # Create the genesis block if the chain is empty
        if not self.chain:
            self.create_genesis_block()
    
    def create_genesis_block(self) -> None:
        """Create the genesis block."""
        genesis_block = Block(0, [], "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        console.print("[green]Genesis block created.[/green]")
    
    def get_latest_block(self) -> Block:
        """Get the latest block in the chain."""
        return self.chain[-1]
    
    def add_transaction(self, transaction: Transaction, public_key) -> bool:
        """Add a transaction to the pending transactions."""
        # Verify the transaction signature
        if not transaction.verify_signature(public_key):
            console.print("[red]Transaction signature verification failed.[/red]")
            return False
        
        self.pending_transactions.append(transaction)
        console.print("[green]Transaction added to pending transactions.[/green]")
        return True
    
    def mine_pending_transactions(self, miner_address: str) -> None:
        """Mine pending transactions and add them to the blockchain."""
        # Create a reward transaction for the miner
        reward_tx = Transaction("SYSTEM", miner_address, self.mining_reward)
        
        # Add reward transaction to pending transactions
        self.pending_transactions.append(reward_tx)
        
        # Create a new block with all pending transactions
        block = Block(
            len(self.chain),
            self.pending_transactions,
            self.get_latest_block().hash
        )
        
        # Mine the block
        block.mine_block(self.difficulty)
        
        # Add the block to the chain
        self.chain.append(block)
        
        # Clear the pending transactions
        self.pending_transactions = []
        
        console.print(f"[green]Block successfully mined! Reward of {self.mining_reward} sent to {miner_address}[/green]")
    
    def is_chain_valid(self) -> bool:
        """Validate the blockchain."""
        # Loop through the chain to check hashes
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if the current block hash is valid
            if current_block.hash != current_block.calculate_hash():
                console.print(f"[red]Block {i} has invalid hash.[/red]")
                return False
            
            # Check if the previous hash reference is correct
            if current_block.previous_hash != previous_block.hash:
                console.print(f"[red]Block {i} has invalid previous hash reference.[/red]")
                return False
            
            # Verify all transactions in the block
            for tx in current_block.transactions:
                if tx.sender == "SYSTEM":  # Skip mining reward transactions
                    continue
                
                # In a real system, we would look up the sender's public key
                # For this demo, we'll skip detailed transaction verification
            
        return True
    
    def get_balance(self, address: str) -> float:
        """Get the balance of an address."""
        balance = 0.0
        
        # Loop through all blocks and transactions
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient == address:
                    balance += tx.amount
                if tx.sender == address:
                    balance -= tx.amount
        
        return balance
    
    def save_to_file(self, filename: str) -> None:
        """Save the blockchain to a file."""
        data = {
            "chain": [block.to_dict() for block in self.chain],
            "pending_transactions": [tx.to_dict() for tx in self.pending_transactions],
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        console.print(f"[green]Blockchain saved to {filename}[/green]")
    
    @classmethod
    def load_from_file(cls, filename: str) -> 'Blockchain':
        """Load blockchain from a file."""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        blockchain = cls(difficulty=data["difficulty"])
        blockchain.mining_reward = data["mining_reward"]
        
        # Clear the genesis block
        blockchain.chain = []
        
        # Load the chain
        for block_data in data["chain"]:
            block = Block.from_dict(block_data)
            blockchain.chain.append(block)
        
        # Load pending transactions
        blockchain.pending_transactions = [
            Transaction.from_dict(tx) for tx in data["pending_transactions"]
        ]
        
        console.print(f"[green]Blockchain loaded from {filename}[/green]")
        return blockchain


def load_keys(directory="keys"):
    """Load keys from files."""
    private_key_path = Path(directory) / "private_key.pem"
    public_key_path = Path(directory) / "public_key.pem"
    
    if not private_key_path.exists() or not public_key_path.exists():
        console.print("[red]Keys not found. Please generate keys first using the crypto_toolkit.[/red]")
        return None, None
    
    with open(private_key_path, 'rb') as f:
        private_key_data = f.read()
    
    with open(public_key_path, 'rb') as f:
        public_key_data = f.read()
    
    private_key = AsymmetricEncryption.load_private_key(private_key_data)
    public_key = AsymmetricEncryption.load_public_key(public_key_data)
    
    return private_key, public_key


def create_genesis_blockchain():
    """Create a new blockchain with genesis block."""
    blockchain = Blockchain(difficulty=4)
    blockchain.save_to_file("blockchain.json")
    return blockchain


def load_or_create_blockchain():
    """Load the blockchain or create a new one if it doesn't exist."""
    blockchain_file = Path("blockchain.json")
    
    if blockchain_file.exists():
        return Blockchain.load_from_file("blockchain.json")
    else:
        return create_genesis_blockchain()


def display_chain(blockchain):
    """Display the blockchain in a nice format."""
    table = Table(title="Blockchain")
    table.add_column("Block", style="cyan")
    table.add_column("Hash", style="green")
    table.add_column("Previous Hash", style="yellow")
    table.add_column("Transactions", style="magenta")
    table.add_column("Timestamp", style="blue")
    
    for block in blockchain.chain:
        table.add_row(
            str(block.index),
            block.hash[:10] + "...",
            block.previous_hash[:10] + "..." if block.previous_hash != "0" else "0",
            str(len(block.transactions)),
            block.timestamp
        )
    
    console.print(table)


def display_transactions(transactions, title="Transactions"):
    """Display transactions in a nice format."""
    table = Table(title=title)
    table.add_column("Sender", style="cyan")
    table.add_column("Recipient", style="green")
    table.add_column("Amount", style="yellow")
    table.add_column("Timestamp", style="blue")
    
    for tx in transactions:
        table.add_row(
            tx.sender,
            tx.recipient,
            str(tx.amount),
            tx.timestamp
        )
    
    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Simple Blockchain Demo")
    parser.add_argument("--address", default="user1", help="Your blockchain address")
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Create a new blockchain
    create_parser = subparsers.add_parser("create", help="Create a new blockchain")
    
    # Show the blockchain
    show_parser = subparsers.add_parser("show", help="Show the blockchain")
    
    # Create a transaction
    tx_parser = subparsers.add_parser("transaction", help="Create a new transaction")
    tx_parser.add_argument("--to", required=True, help="Recipient address")
    tx_parser.add_argument("--amount", type=float, required=True, help="Amount to send")
    
    # Mine transactions
    mine_parser = subparsers.add_parser("mine", help="Mine pending transactions")
    
    # Check balance
    balance_parser = subparsers.add_parser("balance", help="Check address balance")
    balance_parser.add_argument("--address", help="Address to check (defaults to your address)")
    
    # Validate the blockchain
    validate_parser = subparsers.add_parser("validate", help="Validate the blockchain")
    
    args = parser.parse_args()
    
    # Display a header
    console.print(Panel.fit(
        "[bold]Simple Blockchain Demo[/bold]\nDemonstrating cryptographic concepts",
        border_style="cyan"
    ))
    
    # Load keys
    private_key, public_key = load_keys()
    if not private_key or not public_key:
        console.print("[red]Please run './crypto_toolkit.py generate-keypair' first to create keys.[/red]")
        return
    
    if args.command == "create":
        blockchain = create_genesis_blockchain()
        display_chain(blockchain)
    
    elif args.command == "show":
        blockchain = load_or_create_blockchain()
        display_chain(blockchain)
        
        # Show pending transactions if any
        if blockchain.pending_transactions:
            display_transactions(blockchain.pending_transactions, "Pending Transactions")
    
    elif args.command == "transaction":
        blockchain = load_or_create_blockchain()
        
        # Create and sign the transaction
        tx = Transaction(args.address, args.to, args.amount)
        tx.sign(private_key)
        
        # Add the transaction
        if blockchain.add_transaction(tx, public_key):
            console.print(f"[green]Transaction from {args.address} to {args.to} for {args.amount} created.[/green]")
        
        blockchain.save_to_file("blockchain.json")
    
    elif args.command == "mine":
        blockchain = load_or_create_blockchain()
        
        if not blockchain.pending_transactions:
            console.print("[yellow]No pending transactions to mine.[/yellow]")
        else:
            blockchain.mine_pending_transactions(args.address)
            blockchain.save_to_file("blockchain.json")
            
            # Show the updated chain
            display_chain(blockchain)
    
    elif args.command == "balance":
        blockchain = load_or_create_blockchain()
        address = args.address or args.address
        
        balance = blockchain.get_balance(address)
        console.print(f"[green]Balance of {address}: {balance}[/green]")
    
    elif args.command == "validate":
        blockchain = load_or_create_blockchain()
        
        if blockchain.is_chain_valid():
            console.print("[green]Blockchain is valid.[/green]")
        else:
            console.print("[red]Blockchain is invalid![/red]")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 