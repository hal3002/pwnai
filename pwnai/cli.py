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
        help="LLM model configuration to use (e.g., 'openai', 'ollama'). Uses default from models.yaml if not specified",
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

    return parser.parse_args()


def find_models_config():
    """Find the models.yaml configuration file.
    
    Searches in the following locations:
    1. Current working directory
    2. ~/.pwnai/models.yaml (user home directory)
    3. Package-bundled models.yaml
    """
    # Check current directory
    if os.path.exists("models.yaml"):
        return "models.yaml"
    
    # Check user's home directory
    home_config = os.path.expanduser("~/.pwnai/models.yaml")
    if os.path.exists(home_config):
        return home_config
    
    # Use package-bundled version
    try:
        # Replace pkg_resources with importlib.resources
        try:
            # For Python 3.9+
            with importlib.resources.files("pwnai").joinpath("models.yaml") as path:
                return str(path)
        except AttributeError:
            # Fallback for Python 3.8 or earlier
            return str(importlib.resources.path("pwnai", "models.yaml"))
    except Exception as e:
        print(f"Warning: Could not locate models.yaml: {e}")
        return None


def get_available_models():
    """Get the list of available model configurations."""
    config_path = find_models_config()
    
    if not config_path:
        return ["openai"]  # Fallback to default
    
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            return list(config.keys())
    except Exception as e:
        print(f"Warning: Could not load models configuration: {e}")
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
    
    # Find models.yaml and set up LLM configuration
    models_config = find_models_config()
    if models_config:
        logger.debug(f"Using models configuration from: {models_config}")
    
    llm_config = {"model_config": args.model} if args.model else {}
    
    # Initialize the coordinator
    try:
        coordinator = Coordinator(
            binary_path=str(binary_path),
            output_dir=str(output_dir),
            remote_host=remote_host,
            remote_port=remote_port,
            arch=args.arch,
            llm_config=llm_config,
            debug=args.debug,
            user_feedback=args.feedback,
            source_file=args.source
        )
        
        # Initialize and register all agents
        logger.info("Initializing agents...")
        
        # Create initial state for agents
        state = coordinator.state.to_dict()
        
        # Create a single LLM service instance to be shared by all agents
        shared_llm_service = LLMService(**(llm_config))
        logger.debug(f"Created shared LLM service with model config: {args.model or 'default'}")
        
        # Pass the shared_llm_service directly to the agent constructors
        
        # Reversing Agent
        reversing_agent = ReversingAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=llm_config,
            llm_service=shared_llm_service
        )
        coordinator.register_agent("reversing", reversing_agent)
        
        # Debugging Agent
        debugging_agent = DebuggingAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=llm_config,
            llm_service=shared_llm_service
        )
        coordinator.register_agent("debugging", debugging_agent)
        
        # Exploitation Agent
        exploitation_agent = ExploitationAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=llm_config,
            llm_service=shared_llm_service
        )
        coordinator.register_agent("exploitation", exploitation_agent)
        
        # Writeup Agent
        writeup_agent = WriteupAgent(
            state=state,
            binary_path=binary_path,
            output_dir=output_dir,
            llm_config=llm_config,
            llm_service=shared_llm_service
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