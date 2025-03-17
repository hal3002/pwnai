#!/bin/bash
# Utility script to compile challenge binaries locally
# Supports Intel architectures (x86, x86_64)

set -e

# Display usage information
function show_usage {
    echo "Usage: $0 <source_file.c> [options]"
    echo "Options:"
    echo "  --arch ARCH     Target architecture (x86_64, x86). Default: x86_64"
    echo "  --output FILE   Output binary name. Default: <source_name>_<arch>"
    echo "  --output-dir DIR Directory to place compiled binaries. Default: current directory"
    echo "  --extra FLAGS   Additional compiler flags (in quotes)"
    echo "  --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 path/to/overflow.c --arch x86_64"
    echo "  $0 path/to/format.c --arch x86_64 --output my_format"
    echo "  $0 path/to/command.c --arch x86 --extra \"-O2 -Wall\""
    exit 1
}

# Check if source file is provided
if [ $# -lt 1 ]; then
    show_usage
fi

# Get the source file
SOURCE_FILE=$1
shift

if [ ! -f "$SOURCE_FILE" ]; then
    echo "Error: Source file '$SOURCE_FILE' not found."
    exit 1
fi

# Default values
ARCH="x86_64"
OUTPUT_FILE=""
OUTPUT_DIR="."
EXTRA_FLAGS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --extra)
            EXTRA_FLAGS="$2"
            shift 2
            ;;
        --help)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Check if GCC is installed
if ! command -v gcc &> /dev/null; then
    echo "Error: GCC compiler not found. Please install GCC."
    exit 1
fi

# Get source filename without path and extension
SOURCE_NAME=$(basename "$SOURCE_FILE" .c)

# If no output file is specified, use source name + architecture
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="${SOURCE_NAME}_${ARCH}"
fi

# Make output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Set architecture-specific compiler flags
case "$ARCH" in
    "x86")
        ARCH_DEFINES="-m32"
        ;;
    "x86_64")
        ARCH_DEFINES=""
        ;;
    *)
        echo "Error: Unsupported architecture '$ARCH'. Supported: x86_64, x86"
        exit 1
        ;;
esac

# Define compiler flags (same as in tests)
BASE_COMPILER_FLAGS="-fno-stack-protector -no-pie -z execstack"

# Compile the binary
echo "Compiling $SOURCE_FILE for $ARCH architecture..."
COMPILER_CMD="gcc ${ARCH_DEFINES} ${BASE_COMPILER_FLAGS} ${EXTRA_FLAGS} ${SOURCE_FILE} -o ${OUTPUT_DIR}/${OUTPUT_FILE}"
echo "Command: $COMPILER_CMD"

if eval "$COMPILER_CMD"; then
    echo "Compilation successful."
else
    echo "Error: Compilation failed"
    exit 1
fi

# Make the binary executable
chmod +x "${OUTPUT_DIR}/${OUTPUT_FILE}"

# Show file information
echo "Binary details:"
file "${OUTPUT_DIR}/${OUTPUT_FILE}"

# Display execution instructions
echo ""
echo "To run the binary:"
echo "${OUTPUT_DIR}/${OUTPUT_FILE}"
echo "" 