#!/usr/bin/env python3
"""
Test script to verify that the test runner works correctly.
"""

import os
import unittest
from pathlib import Path

class TestRunner(unittest.TestCase):
    """Test case to verify that the test runner works correctly."""
    
    def test_challenge_files_exist(self):
        """Test that the challenge files exist."""
        # Get the challenges directory
        challenges_dir = Path(__file__).parent / "challenges"
        
        # Check if the directory exists
        self.assertTrue(challenges_dir.exists(), "Challenges directory does not exist")
        
        # Check if the source files exist
        overflow_source = challenges_dir / "overflow.c"
        format_source = challenges_dir / "format.c"
        
        self.assertTrue(overflow_source.exists(), f"{overflow_source} does not exist")
        self.assertTrue(format_source.exists(), f"{format_source} does not exist")
    
    def test_compiled_binaries_exist(self):
        """Test that the compiled binaries exist."""
        # This test will pass only if the binaries have been compiled
        # Get the challenges directory
        challenges_dir = Path(__file__).parent / "challenges"
        
        # Check if the binaries exist
        overflow_binary = challenges_dir / "overflow"
        format_binary = challenges_dir / "format"
        
        # Print a message if the binaries don't exist
        if not overflow_binary.exists():
            print(f"Warning: {overflow_binary} does not exist. Run the test runner first.")
        
        if not format_binary.exists():
            print(f"Warning: {format_binary} does not exist. Run the test runner first.")
        
        # Skip the test if the binaries don't exist
        if not overflow_binary.exists() or not format_binary.exists():
            self.skipTest("Binaries not compiled yet. Run the test runner first.")
        
        # Check if the binaries are executable
        self.assertTrue(os.access(overflow_binary, os.X_OK), f"{overflow_binary} is not executable")
        self.assertTrue(os.access(format_binary, os.X_OK), f"{format_binary} is not executable")

if __name__ == "__main__":
    unittest.main() 