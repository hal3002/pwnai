#!/usr/bin/env python3
"""
Test runner script for PwnAI.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

def compile_challenges():
    """Compile the challenge binaries."""
    print("Compiling challenge binaries...")
    
    # Get the challenges directory
    challenges_dir = Path("pwnai/tests/challenges")
    
    # Create the directory if it doesn't exist
    challenges_dir.mkdir(parents=True, exist_ok=True)
    
    # List of challenges to compile
    challenges = [
        {
            "source": "overflow.c",
            "binary": "overflow",
            "compile_cmd": [
                "gcc", 
                "-fno-stack-protector", 
                "-no-pie", 
                "-o", "{binary}", 
                "{source}"
            ]
        },
        {
            "source": "format.c",
            "binary": "format",
            "compile_cmd": [
                "gcc", 
                "-o", "{binary}", 
                "{source}"
            ]
        },
        {
            "source": "command.c",
            "binary": "command",
            "compile_cmd": [
                "gcc", 
                "-o", "{binary}", 
                "{source}"
            ]
        }
    ]
    
    # Compile each challenge
    for challenge in challenges:
        source_path = challenges_dir / challenge["source"]
        binary_path = challenges_dir / challenge["binary"]
        
        if source_path.exists():
            # Format the compile command
            compile_cmd = [
                cmd.format(source=source_path, binary=binary_path)
                for cmd in challenge["compile_cmd"]
            ]
            
            try:
                subprocess.run(compile_cmd, check=True)
                print(f"Successfully compiled {binary_path}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to compile {source_path}: {e}")
                return False
        else:
            print(f"Source file {source_path} not found")
            return False
    
    return True

def install_basic_dependencies():
    """Install basic dependencies required for testing."""
    print("Installing basic dependencies...")
    
    # Install pytest and pytest-cov
    cmd = [sys.executable, "-m", "pip", "install", "pytest>=7.0.0", "pytest-cov>=4.1.0", "colorama>=0.4.6"]
    
    try:
        subprocess.run(cmd, check=True)
        print("Successfully installed basic dependencies")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install basic dependencies: {e}")
        return False

def run_tests(args):
    """Run the tests."""
    # Install basic dependencies
    if args.install_deps:
        if not install_basic_dependencies():
            print("Failed to install basic dependencies. Exiting.")
            return 1
    
    # Compile the challenges
    if not compile_challenges():
        print("Failed to compile challenges. Exiting.")
        return 1
    
    # Build the pytest command
    cmd = [sys.executable, "-m", "pytest"]
    
    # Add verbosity
    if args.verbose:
        cmd.append("-v")
    
    # Add specific test if provided
    if args.test:
        cmd.append(args.test)
    else:
        cmd.append("pwnai/tests")
    
    # Run the tests
    print(f"Running tests: {' '.join(cmd)}")
    return subprocess.run(cmd).returncode

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run PwnAI tests")
    parser.add_argument("-t", "--test", help="Specific test file or directory to run")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-i", "--install-deps", action="store_true", help="Install basic dependencies")
    
    args = parser.parse_args()
    
    return run_tests(args)

if __name__ == "__main__":
    sys.exit(main()) 