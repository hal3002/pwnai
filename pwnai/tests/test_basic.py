#!/usr/bin/env python3
"""
Basic tests for PwnAI functionality without Docker.
"""

import os
import sys
import pytest
from pathlib import Path

# Add the parent directory to the path so we can import pwnai
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pwnai.core.coordinator import Coordinator
from pwnai.utils.logger import setup_logger
import logging

# Setup test logger
logger = setup_logger(logging.DEBUG)

# Path to test binaries
TEST_BINARIES_DIR = Path(__file__).parent / "challenges"


def ensure_test_binaries():
    """Ensure test binaries directory exists and has test cases."""
    TEST_BINARIES_DIR.mkdir(exist_ok=True)
    
    # Check if we have at least one test binary
    binaries = list(TEST_BINARIES_DIR.glob("*.bin"))
    if not binaries:
        logger.warning(f"No test binaries found in {TEST_BINARIES_DIR}. Some tests may be skipped.")
    return binaries


@pytest.fixture(scope="session")
def test_binaries():
    """Fixture to provide test binaries."""
    return ensure_test_binaries()


def test_coordinator_initialization():
    """Test that the Coordinator can be initialized properly."""
    output_dir = Path("./test_output")
    output_dir.mkdir(exist_ok=True)
    
    # Mock binary path - doesn't need to exist for this test
    binary_path = Path("./mock_binary.bin")
    
    coordinator = Coordinator(
        binary_path=binary_path,
        output_dir=output_dir,
        remote_host=None,
        remote_port=None,
        arch="x86_64",
        llm_config={"model_config": "openai"}
    )
    
    assert coordinator is not None
    assert coordinator.binary_path == binary_path
    assert coordinator.output_dir == output_dir
    assert coordinator.arch == "x86_64"


def test_find_models_config():
    """Test the find_models_config function."""
    from pwnai.cli import find_models_config
    
    config_path = find_models_config()
    # We expect some config path to be found, either in the package
    # or in the user's home directory
    assert config_path is not None
    assert os.path.exists(config_path)


@pytest.mark.skipif(not ensure_test_binaries(), reason="No test binaries available")
def test_simple_binary_analysis(test_binaries):
    """Test simple binary analysis with an actual binary."""
    if not test_binaries:
        pytest.skip("No test binaries available")
    
    # Use the first available test binary
    binary_path = test_binaries[0]
    output_dir = Path("./test_output")
    output_dir.mkdir(exist_ok=True)
    
    coordinator = Coordinator(
        binary_path=binary_path,
        output_dir=output_dir,
        remote_host=None,
        remote_port=None,
        arch=None,  # Auto-detect
        llm_config={"model_config": "openai"}
    )
    
    # This is a simple check that the binary info can be extracted
    binary_info = coordinator.extract_binary_info()
    assert binary_info is not None
    assert "arch" in binary_info
    assert "format" in binary_info


if __name__ == "__main__":
    # Run the tests directly if the file is executed
    pytest.main(["-xvs", __file__]) 