# Contributing to PwnAI

Thank you for considering contributing to PwnAI! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and considerate when interacting with other contributors. We aim to foster an inclusive and welcoming community.

## How to Contribute

1. **Fork the repository** and create your branch from `main`.
2. **Set up your development environment** using the provided Docker container.
3. **Make your changes** and ensure they follow the project's coding conventions.
4. **Add tests** for any new functionality.
5. **Ensure all tests pass** by running `pytest`.
6. **Submit a pull request** with a clear description of the changes and any relevant issue numbers.

## Development Environment

We recommend using the provided Docker development container:

```bash
# Clone the repository
git clone https://github.com/yourusername/pwnai.git
cd pwnai

# Build and start the development container
# If you're using VS Code:
code .
# Then use the "Reopen in Container" option

# Or build and run manually:
docker build -t pwnai-dev .
docker run -it -v $(pwd):/workspace pwnai-dev
```

## Running Tests

```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
pytest
```

## Coding Style

We follow the PEP 8 style guide for Python code. You can use the following tools to ensure your code meets our style requirements:

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
pylint pwnai

# Check types
mypy pwnai
```

## Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable.
2. Update the documentation if you're changing functionality.
3. The PR should work for Python 3.8, 3.9, and 3.10.
4. PRs require approval from at least one maintainer before being merged.

## Release Process

Releases are managed by the project maintainers. Version numbers follow [Semantic Versioning](https://semver.org/).

## Getting Help

If you have questions or need help with the contribution process, please open an issue with the "question" label. 