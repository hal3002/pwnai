# PwnAI: LLM-Based CTF Exploitation Solver

PwnAI is an advanced multi-agent system that uses Large Language Models (LLMs) to automatically solve binary exploitation challenges in Capture The Flag (CTF) competitions.

## Overview

This system leverages multiple specialized LLM agents that collaborate to:
- Analyze binaries for vulnerabilities
- Discover and verify exploitation paths
- Develop working exploits
- Generate detailed solution write-ups

PwnAI is designed as a standard Python package that you can easily integrate into your CTF workflow.

## Key Features

- Multi-agent collaboration between specialized agents:
  - Reversing Agent (static analysis)
  - Debugging Agent (dynamic analysis)
  - Exploitation Agent (exploit development)
  - Writeup Agent (documentation generation)
- Integrations with industry-standard tools:
  - GDB with Pwndbg
  - Radare2
  - Pwntools
- Support for multiple architectures (x86, x86_64)
- Extensible framework for adding new architectures and vulnerability types
- Fully open source with no built-in safeguards or usage restrictions

## Installation

### Prerequisites

PwnAI requires the following tools to be installed on your system:
- Python 3.8+
- GDB with Pwndbg (for dynamic analysis)
- Radare2 (for static analysis)
- Various compiler toolchains for the target architectures (gcc, g++)

### Install from PyPI

```bash
# Install from PyPI
pip install pwnai

# Set up your configuration (creates ~/.pwnai/models.yaml)
pwnai-config
```

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/username/pwnai.git
cd pwnai

# Install the package
pip install -e .
```

This will install PwnAI as a local Python package that can be used from any directory.

### Development Installation

For development, you may want to install additional dependencies:

```bash
# Install development dependencies
pip install -e ".[dev]"
```

## Usage

```bash
# Basic usage
pwnai /path/to/binary --output-dir ./results

# With additional options
pwnai /path/to/binary --debug --model openai --output-dir ./results

# Remote challenge
pwnai /path/to/binary --remote ctf.example.com:1337 --output-dir ./results
```

## Configuration

PwnAI uses a configuration file for LLM settings. When you run `pwnai-config`, it creates a configuration file at `~/.pwnai/models.yaml`. You can edit this file to customize your LLM configurations:

```yaml
# Example configuration
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
```

## Command-line Options

```
usage: pwnai [-h] [--remote REMOTE] [--arch {x86,x86_64}] [--debug] --output-dir OUTPUT_DIR [--model MODEL] binary

PwnAI: LLM-Based CTF Exploitation Solver

positional arguments:
  binary             Path to the target binary

required arguments:
  --output-dir OUTPUT_DIR
                    Directory to store output files
  
optional arguments:
  --remote REMOTE    Remote host:port for the challenge (e.g., 'ctf.example.com:1337')
  --arch {x86,x86_64}
                    Binary architecture (auto-detected if not specified)
  --debug            Enable debug logging
  --model MODEL      LLM model configuration to use
```

## Development Utilities

The project includes utility scripts for development in the `utils/` directory:

```bash
# Run tests
python utils/run_tests.py -v

# Compile a challenge binary
bash utils/compile-challenge.sh path/to/source.c --output-dir ./my_binaries
```

## Project Structure

```
pwnai/
├── agents/           # Implementation of specialized LLM agents
├── core/             # Core system components (coordinator, state management)
├── tools/            # Tool integrations (GDB, Radare2, Pwntools wrappers)
├── utils/            # Utility functions and helpers
└── tests/            # Test suite
    ├── challenges/   # Sample binaries for testing
    └── unit/         # Unit tests for system components
```

## Running Tests

To run the test suite:

```bash
# Run all tests
python -m pytest

# Run specific tests
python -m pytest pwnai/tests/test_overflow.py
```

## Local Operation

PwnAI now runs entirely as a standalone Python library without any Docker dependency. All functionality that previously required Docker containers now runs directly on the host system. This simplifies installation and operation, making PwnAI easier to use and integrate with other tools.

The project still maintains a development Docker environment (Dockerfile and docker-compose.yml) for those who prefer containerized development, but this is entirely optional.

### Key Changes

- All Docker-dependent code has been removed
- Binary analysis and exploitation now run directly on the host
- The command line interface is simplified
- All tests can be run locally without Docker
- Challenge compilation is done natively with local GCC

## Docker (Optional Development Environment)

PwnAI runs fully as a standalone Python library without Docker dependency. However, we still provide a Docker environment for development purposes:

```bash
# Clone the repository
git clone https://github.com/username/pwnai.git
cd pwnai

# Build the Docker image
docker build -t pwnai:dev .

# Run the Docker container (mounting the current directory to /app)
docker run -it --rm -v "$(pwd):/app" pwnai:dev
```

The Docker environment includes all necessary dependencies for development and testing.

## Disclaimer

This tool is designed for educational purposes and for solving legitimate CTF challenges. Users are responsible for ensuring they use this tool ethically and in compliance with applicable laws and regulations.

## License

[MIT License](LICENSE)

# PwnAI Test Suite

This repository contains test scripts for PwnAI, a tool for automated exploit development.

## Setup

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Compile the vulnerable programs:

```bash
cd pwnai/tests/challenges
gcc -fno-stack-protector -no-pie -o overflow overflow.c
gcc -o format format.c
gcc -o command command.c
```

Alternatively, you can use the provided test runner script which will compile the challenges automatically:

```bash
./run_tests.py
```

## Running Tests

To run all tests:

```bash
python -m pytest pwnai/tests
```

To run a specific test:

```