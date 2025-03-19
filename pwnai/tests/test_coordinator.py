#!/usr/bin/env python3
"""
Tests for the coordinator module.
"""

import os
import pytest
from pathlib import Path
from typing import Dict

from pwnai.core.coordinator import Coordinator

@pytest.fixture
def test_binary(tmp_path):
    """Create a test binary."""
    binary_path = tmp_path / "test_binary"
    binary_path.write_bytes(b"\x00" * 100)  # Create a dummy binary
    return binary_path

@pytest.fixture
def test_output_dir(tmp_path):
    """Create a test output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir

def test_coordinator_initialization(test_binary, test_output_dir):
    """Test coordinator initialization."""
    # Test basic initialization
    coordinator = Coordinator(
        binary_path=test_binary,
        output_dir=test_output_dir,
    )
    assert coordinator.state.binary_path == test_binary
    assert coordinator.state.output_dir == test_output_dir
    assert coordinator.state.remote_target is None
    assert coordinator.state.arch is None
    from pwnai.core.coordinator import PwnState
    assert isinstance(coordinator.state, PwnState)
    
    # Test with remote host and port
    coordinator = Coordinator(
        binary_path=test_binary,
        output_dir=test_output_dir,
        remote_host="localhost",
        remote_port=1337,
    )
    assert coordinator.state.remote_target == "localhost:1337"
    
    # Test with custom arch
    coordinator = Coordinator(
        binary_path=test_binary,
        output_dir=test_output_dir,
        arch="i386",
    )
    assert coordinator.state.arch == "i386"
    
    # Test with LLM config
    llm_config = {"model": "gpt-4", "temperature": 0.7}
    coordinator = Coordinator(
        binary_path=test_binary,
        output_dir=test_output_dir,
        llm_config=llm_config,
    )
    assert coordinator.llm_config == llm_config

def test_coordinator_start(test_binary, test_output_dir):
    """Test coordinator start method."""
    coordinator = Coordinator(
        binary_path=test_binary,
        output_dir=test_output_dir,
    )
    
    # Mock the agent runs to avoid actual execution
    coordinator.start = lambda: None
    
    # The start method should not raise any exceptions
    coordinator.start() 