FROM --platform=linux/amd64 ubuntu:noble

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install common essential tools
RUN apt-get update && apt-get -qqy dist-upgrade
RUN apt-get install -qqy \
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
    libffi-dev \
    pkg-config \
    libc6-dbg \
    gdbserver \
    file \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add i386 architecture support first
RUN dpkg --add-architecture i386 && \
    apt-get update

# Install architecture-specific packages for x86 and x86_64 (consolidated)
RUN apt-get install -qqy \
    gcc-multilib \
    g++-multilib \
    libc6-dev-i386 \
    lib32z1-dev \
    lib32gcc-9-dev \
    binutils-multiarch \
    libc6:i386 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment for Python packages
RUN python3 -m virtualenv /opt/python

# Add the virtual environment to PATH
ENV PATH="/opt/python/bin:$PATH"

# Ensure setuptools is installed in the virtual environment
RUN /opt/python/bin/pip install --no-cache-dir setuptools

# Copy setup.py to install dependencies
COPY setup.py .
COPY README.md .
COPY MANIFEST.in .

# Install required Python packages
RUN /opt/python/bin/pip install --no-cache-dir -e .[dev]

# Clean up
RUN rm -f setup.py README.md MANIFEST.in

