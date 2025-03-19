#!/bin/bash
set -e

# Update apt and install essential packages
echo "Updating package lists and installing essential tools..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update && sudo apt-get -qqy dist-upgrade
sudo apt-get install -qqy \
    python3 \
    python3-pip \
    python3-dev \
    git \
    build-essential \
    gcc \
    g++ \
    gdb \
    wget \
    curl \
    cmake \
    radare2 \
    libssl-dev \
    libcapstone-dev \
    python3-virtualenv \
    python3-setuptools \
    python3-venv \
    libffi-dev \
    pkg-config \
    libc6-dbg \
    gdbserver \
    file \
    libglib2.0-dev

# Add i386 architecture support
echo "Adding i386 architecture support..."
sudo dpkg --add-architecture i386
sudo apt-get update

# Install architecture-specific packages
echo "Installing architecture-specific packages..."
sudo apt-get install -qqy \
    gcc-multilib \
    g++-multilib \
    libc6-dev-i386 \
    lib32z1-dev \
    lib32gcc-9-dev \
    binutils-multiarch \
    libc6:i386 \
    libc6-dbg:i386

# Clean up apt cache
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

# Create a virtual environment for Python packages
echo "Setting up Python virtual environment..."
python3 -m virtualenv ~/pwnai-env

# Install Python dependencies
echo "Installing Python dependencies..."
source ~/pwnai-env/bin/activate
pip install --no-cache-dir setuptools
pip install --no-cache-dir pwntools r2pipe "openai>=1.0.0" python-dotenv numpy colorlog pyyaml requests capstone ropgadget
pip install --no-cache-dir pytest pytest-cov black isort pylint mypy

# Install pwndbg
echo "Installing pwndbg..."
if [ ! -d ~/pwndbg ]; then
    git clone https://github.com/pwndbg/pwndbg.git ~/pwndbg
    cd ~/pwndbg
    ./setup.sh
fi

echo "Setup complete! To activate the virtual environment, run:"
echo "source ~/pwnai-env/bin/activate" 