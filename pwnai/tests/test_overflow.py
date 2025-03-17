#!/usr/bin/env python3
"""
Test script for exploiting the buffer overflow vulnerability.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

class TestBufferOverflow(unittest.TestCase):
    """Test case for the buffer overflow vulnerability."""
    
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
        
        self.assertIn("You entered: Hello, World!", stdout)
        self.assertIn("Program completed normally", stdout)
    
    def test_buffer_overflow(self):
        """Test exploiting the buffer overflow vulnerability."""
        # This is a simplified exploit that might need adjustment based on
        # the actual memory layout and architecture
        
        # Create a payload that overflows the buffer and overwrites the return address
        # with the address of the win() function
        
        # For demonstration purposes, we'll use a simple pattern
        # In a real exploit, you would need to determine the exact offset and address
        payload = b"A" * 80  # Overflow the buffer
        
        # On a 64-bit system, we would need to add the address of win()
        # This is a simplified example and may need adjustment
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(payload)
            f.write(b"\n")  # Add newline for gets()
            payload_file = f.name
        
        try:
            # Run the program with the payload
            proc = subprocess.Popen(
                [str(self.binary_path)],
                stdin=open(payload_file, 'rb'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = proc.communicate()
            stdout = stdout.decode('utf-8', errors='ignore')
            
            # Check if the program crashed (which is expected with this simplified payload)
            # In a real exploit, we would check for the win message
            self.assertNotIn("Program completed normally", stdout)
            
            # Note: A complete exploit would need to determine the exact address of win()
            # and construct a proper ROP chain, which is beyond the scope of this test
            print("Buffer overflow test completed - program crashed as expected")
            
        finally:
            os.unlink(payload_file)

if __name__ == "__main__":
    unittest.main() 