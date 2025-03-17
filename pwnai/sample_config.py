#!/usr/bin/env python3
"""
Utility to set up PwnAI configuration in the user's home directory.
"""

import os
import sys
import shutil
from pathlib import Path
import pkg_resources


def setup_config():
    """Set up the PwnAI configuration in the user's home directory."""
    # Create .pwnai directory in user's home
    home_dir = Path.home() / ".pwnai"
    home_dir.mkdir(exist_ok=True)
    
    # Path to store the models.yaml file
    target_path = home_dir / "models.yaml"
    
    # Check if config already exists
    if target_path.exists():
        print(f"Configuration already exists at: {target_path}")
        overwrite = input("Do you want to overwrite it? (y/n): ").lower().strip() == 'y'
        if not overwrite:
            print("Keeping existing configuration.")
            return True
    
    # Find the models.yaml file from various locations
    # Try multiple potential locations
    possible_locations = [
        # Package installed location
        pkg_resources.resource_filename("pwnai", "models.yaml"),
        # Current directory
        os.path.join(os.getcwd(), "models.yaml"),
        # Project root if running from source
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models.yaml"),
        # Inside the package directory
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "models.yaml"),
    ]
    
    for models_yaml in possible_locations:
        if os.path.exists(models_yaml):
            # Copy to user's home directory
            shutil.copy(models_yaml, target_path)
            print(f"Config file created at: {target_path}")
            print(f"You can edit this file to customize your LLM configurations.")
            print(f"Example settings for different models:")
            print("  - OpenAI API: Add your API key to the openai section")
            print("  - Ollama local models: Update the URL if needed")
            return True
            
    # If no config found, create a minimal one
    print("Could not find models.yaml template. Creating a minimal configuration.")
    with open(target_path, 'w') as f:
        f.write("""# PwnAI Model Configuration
# Define different model providers and configurations

openai:
  url: https://api.openai.com/v1
  model: gpt-4o
  temperature: 0.2
  system_prompt_prefix: "You are a binary exploitation expert assistant helping solve CTF challenges."
  default: true

ollama:
  url: http://localhost:11434/api/chat
  model: llama3:70b
  temperature: 0.2
  num_ctx: 16384
  system_prompt_prefix: "You are a binary exploitation expert assistant helping solve CTF challenges."
""")
    print(f"Created minimal configuration at: {target_path}")
    print("Please edit this file to configure your preferred LLM settings.")
    return True


def main():
    """Main entry point."""
    print("Setting up PwnAI configuration...")
    if setup_config():
        print("Configuration setup complete!")
        return 0
    else:
        print("Configuration setup failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 