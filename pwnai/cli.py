#!/usr/bin/env python3
"""
Command-line interface for PwnAI.
"""

import argparse
import logging
import os
import sys
import yaml
import importlib.resources
from pathlib import Path
import re

from pwnai.core.coordinator import Coordinator
from pwnai.utils.logger import setup_logger
from pwnai.agents import ReversingAgent, DebuggingAgent, ExploitationAgent, WriteupAgent
from pwnai.utils.llm_service import LLMService


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PwnAI: LLM-Based CTF Exploitation Solver"
    )
    parser.add_argument(
        "binary",
        type=str,
        help="Path to the target binary",
    )
    parser.add_argument(
        "--remote",
        type=str,
        help="Remote host:port for the challenge (e.g., 'ctf.example.com:1337')",
    )
    parser.add_argument(
        "--arch",
        type=str,
        choices=["x86", "x86_64"],
        help="Binary architecture (auto-detected if not specified)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Directory to store output files",
    )
    parser.add_argument(
        "--model",
        type=str,
        help="Default LLM model provider to use (e.g., 'openai', 'claude'). Overrides the default provider in config file.",
    )
    parser.add_argument(
        "--feedback",
        type=str,
        help="User feedback about the challenge goal (e.g., 'The goal is to get the binary to print \"You win!\"')",
    )
    parser.add_argument(
        "--source",
        type=str,
        help="Path to the source code file of the binary (if available)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=os.path.expanduser("~/.pwnai/config.yml"),
        help="Path to the configuration file (default: ~/.pwnai/config.yml)",
    )
    parser.add_argument(
        "--shellcode",
        type=str,
        help="Path to a binary file containing shellcode to use in the final stage of the exploit",
    )

    return parser.parse_args()


def find_config(custom_path=None):
    """Find the configuration file.
    
    Args:
        custom_path: Custom path to the configuration file specified via command line
    
    Searches in the following locations:
    1. Custom path from command line argument
    2. Current working directory (config.yml or models.yaml)
    3. ~/.pwnai/ directory (config.yml or models.yaml)
    4. Package-bundled configuration
    """
    # Check if custom path is provided
    if custom_path:
        if os.path.exists(custom_path):
            return custom_path
        else:
            print(f"Warning: Specified config file not found at {custom_path}")
    
    # Check current directory
    if os.path.exists("config.yml"):
        return "config.yml"
    
    # Legacy support for models.yaml
    if os.path.exists("models.yaml"):
        return "models.yaml"
    
    # Check user's home directory
    home_config = os.path.expanduser("~/.pwnai/config.yml")
    if os.path.exists(home_config):
        return home_config
    
    # Legacy support for models.yaml in home directory
    home_legacy = os.path.expanduser("~/.pwnai/models.yaml")
    if os.path.exists(home_legacy):
        return home_legacy
    
    # Use package-bundled version
    try:
        # Replace pkg_resources with importlib.resources
        try:
            # For Python 3.9+
            with importlib.resources.files("pwnai").joinpath("config.yml") as path:
                if os.path.exists(path):
                    return str(path)
            # Try legacy models.yaml
            with importlib.resources.files("pwnai").joinpath("models.yaml") as path:
                if os.path.exists(path):
                    return str(path)
        except AttributeError:
            # Fallback for Python 3.8 or earlier
            if importlib.resources.is_resource("pwnai", "config.yml"):
                return str(importlib.resources.path("pwnai", "config.yml"))
            # Try legacy models.yaml
            if importlib.resources.is_resource("pwnai", "models.yaml"):
                return str(importlib.resources.path("pwnai", "models.yaml"))
    except Exception as e:
        print(f"Warning: Could not locate configuration file: {e}")
        return None


def get_available_models():
    """Get the list of available model configurations."""
    config_path = find_config()
    
    if not config_path:
        return ["openai"]  # Fallback to default
    
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            
            # Check if using new config format with providers section
            if "providers" in config:
                return list(config["providers"].keys())
            
            # Legacy format
            return list(config.keys())
    except Exception as e:
        print(f"Warning: Could not load configuration: {e}")
        return ["openai"]  # Fallback to default


def fix_exploit_files(output_dir: Path) -> None:
    """
    Fix any existing exploit.py files with incorrect process() calls.
    
    Args:
        output_dir: Directory containing the exploit files
    """
    exploit_file = output_dir / "exploit.py"
    
    if not exploit_file.exists():
        return
        
    try:
        with open(exploit_file, 'r') as f:
            content = f.read()
            
        # Fix common issues with process() calls
        fixed_content = re.sub(
            r'process\s*\(\s*context\.binary\s*\)', 
            r'process([context.binary.path])', 
            content
        )
        fixed_content = re.sub(
            r'process\s*\(\s*[\'"](.+?)[\'"]\s*\)', 
            r'process([\1])', 
            fixed_content
        )
        
        # Only write back if changes were made
        if fixed_content != content:
            with open(exploit_file, 'w') as f:
                f.write(fixed_content)
            logger.info(f"Fixed process() calls in {exploit_file}")
    except Exception as e:
        logger.warning(f"Failed to fix process() calls in {exploit_file}: {e}")


def main():
    """Main entry point for PwnAI."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logger = setup_logger(level=log_level)
    
    logger.info("Starting PwnAI")
    
    # Validate binary path
    binary_path = Path(args.binary)
    if not binary_path.exists():
        logger.error(f"Binary not found: {args.binary}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Parse remote host:port if provided
    remote_host, remote_port = None, None
    if args.remote:
        try:
            remote_host, remote_port = args.remote.split(":")
            remote_port = int(remote_port)
        except ValueError:
            logger.error(f"Invalid remote format: {args.remote}. Use 'host:port'")
            sys.exit(1)
    
    # Find config.yml/models.yaml and set up LLM configuration
    config_path = find_config(args.config)
    if config_path:
        logger.debug(f"Using configuration from: {config_path}")
    
    # Initialize the coordinator
    try:
        # Create base LLM config that will be used by the coordinator
        base_llm_config = {"model_config": args.model} if args.model else {}
        base_llm_config["config_path"] = args.config  # Use the specified config file
        
        coordinator = Coordinator(
            binary_path=str(binary_path),
            output_dir=str(output_dir),
            remote_host=remote_host,
            remote_port=remote_port,
            arch=args.arch,
            debug=args.debug,
            llm_config=base_llm_config,
            user_feedback=args.feedback,
            source_file=args.source,
            shellcode_file=args.shellcode
        )
        
        # Initialize and register all agents
        logger.info("Initializing agents...")
        
        # Create initial state for agents
        state = coordinator.state.to_dict()
        
        # Create base LLM config with just the model provider override if specified
        base_llm_config = {"model_config": args.model} if args.model else {}
        base_llm_config["config_path"] = config_path  # Use the found config file
        
        logger.debug(f"Using config file: {config_path}")
        if args.model:
            logger.debug(f"Overriding default provider with: {args.model}")
        
        # Create agent-specific configurations
        reversing_llm_config = base_llm_config.copy()
        reversing_llm_config["agent_type"] = "reversing"
        
        debugging_llm_config = base_llm_config.copy()
        debugging_llm_config["agent_type"] = "debugging"
        
        exploitation_llm_config = base_llm_config.copy()
        exploitation_llm_config["agent_type"] = "exploitation"
        
        writeup_llm_config = base_llm_config.copy()
        writeup_llm_config["agent_type"] = "writeup"
        
        # Log agent configurations
        logger.debug(f"Initializing agents with configurations from {config_path}")
        
        # Reversing Agent
        reversing_agent = ReversingAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=reversing_llm_config
        )
        coordinator.register_agent("reversing", reversing_agent)
        
        # Debugging Agent
        debugging_agent = DebuggingAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=debugging_llm_config
        )
        coordinator.register_agent("debugging", debugging_agent)
        
        # Exploitation Agent
        exploitation_agent = ExploitationAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=exploitation_llm_config
        )
        coordinator.register_agent("exploitation", exploitation_agent)
        
        # Writeup Agent
        writeup_agent = WriteupAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=writeup_llm_config
        )
        coordinator.register_agent("writeup", writeup_agent)
        
        logger.info("All agents initialized and registered")
        
        # Start the exploitation process
        result = coordinator.start()
        
        # Fix any exploit files that might have been generated
        fix_exploit_files(output_dir)
        
        logger.info(f"Exploitation completed. Check {output_dir} for results.")
        
        if result.get('flag'):
            logger.info(f"Flag found: {result['flag']}")
        
        return 0
    
    except Exception as e:
        logger.exception(f"Error during exploitation: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 