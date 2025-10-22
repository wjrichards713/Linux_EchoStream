#!/bin/bash

# EchoStream Installation and Run Script for Raspberry Pi 5
# This script installs all dependencies and runs the EchoStream audio application

set -e  # Exit on any error
set -o pipefail

echo "=========================================="
echo "EchoStream Installation Script for RPi 5"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status()  { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running on Raspberry Pi
print_status "Checking if running on Raspberry Pi..."
if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
    print_warning "This script is designed for Raspberry Pi. Continuing anyway..."
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root. Please run as a regular user."
    exit 1
fi

# Update package manager
print_status "Updating package manager..."
sudo apt update -y
print_status "Upgrading system packages..."
sudo apt upgrade -y

# Install essential build tools
print_status "Installing build essentials..."
sudo apt install -y build-essential cmake git pkg-config wget curl make

# Install audio dependencies
print_status "Installing audio libraries..."
sudo apt install -y libportaudio2 libportaudiocpp0 portaudio19-dev alsa-utils pulseaudio pulseaudio-utils

# Install Opus codec
print_status "Installing Opus codec..."
sudo apt install -y libopus-dev libopus0

# Install OpenSSL for encryption
print_status "Installing OpenSSL..."
sudo apt install -y libssl-dev openssl

# Install JSON-C library
print_status "Installing JSON-C library..."
sudo apt install -y libjson-c-dev libjson-c5

# Install cJSON library (alternative JSON parser)
print_status "Installing cJSON library..."
sudo apt install -y libcjson-dev libcjson1

# Verify cJSON installation
print_status "Verifying cJSON installation..."
if dpkg -l | grep -q "^ii.*libcjson-dev"; then
    print_success "libcjson-dev package is installed"
else
    print_error "libcjson-dev package is NOT installed"
fi

if dpkg -l | grep -q "^ii.*libcjson1"; then
    print_success "libcjson1 package is installed"
else
    print_error "libcjson1 package is NOT installed"
fi

# Show cJSON header locations
print_status "Searching for cJSON headers..."
find /usr/include -name "*cjson*" -type f 2>/dev/null | head -5
find /usr/local/include -name "*cjson*" -type f 2>/dev/null | head -5


# Install FFTW3 library for tone detection
print_status "Installing FFTW3 library for FFT operations..."
sudo apt install -y libfftw3-dev libfftw3-double3 libfftw3-single3

# Install cURL library
print_status "Installing cURL library..."
sudo apt install -y libcurl4-openssl-dev curl

# Install WebSockets library
print_status "Installing WebSockets library..."
sudo apt install -y libwebsockets-dev

# Ensure pthread support (usually included with build-essential)
print_status "Ensuring pthread support..."
sudo apt install -y libc6-dev

# Install GPIO utilities for RPi 5
print_status "Installing GPIO utilities for RPi 5..."
sudo apt install -y raspi-gpio gpiod libgpiod-dev

# Install additional development libraries
print_status "Installing additional development libraries..."
sudo apt install -y libasound2-dev libpulse-dev libsndfile1-dev

# Install math libraries for FFT operations
print_status "Installing math libraries..."
sudo apt install -y libblas-dev liblapack-dev

# Check if main.c exists (modular structure)
if [ ! -f "main.c" ]; then
    print_error "main.c not found in current directory!"
    print_error "Please ensure you're running this script from the EchoStream directory."
    exit 1
fi

# Check for all required source files (including tone detection)
required_files=("main.c" "audio.c" "websocket.c" "gpio.c" "udp.c" "config.c" "crypto.c" "tone_detect.c")
missing_files=()

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -ne 0 ]; then
    print_error "Missing required source files:"
    for file in "${missing_files[@]}"; do
        print_error "  - $file"
    done
    print_error "Please ensure you're running this script from the complete EchoStream directory."
    exit 1
fi

print_success "All dependencies installed successfully!"

# Verify tone detection dependencies

# Check cJSON library and headers
cjson_found=false
cjson_header_found=false

# Check for cJSON library
if pkg-config --exists libcjson; then
    print_success "cJSON library found via pkg-config"
    cjson_found=true
elif [ -f "/usr/lib/aarch64-linux-gnu/libcjson.so" ] || [ -f "/usr/lib/x86_64-linux-gnu/libcjson.so" ] || [ -f "/usr/lib/arm-linux-gnueabihf/libcjson.so" ]; then
    print_success "cJSON library found in system libraries"
    cjson_found=true
elif ldconfig -p | grep -q libcjson; then
    print_success "cJSON library found via ldconfig"
    cjson_found=true
fi

# Check for cJSON headers (note: actual file is cJSON.h with capital C)
cjson_header_path=""
if [ -f "/usr/include/cjson/cJSON.h" ]; then
    print_success "cJSON header found at /usr/include/cjson/cJSON.h"
    cjson_header_found=true
    cjson_header_path="/usr/include/cjson/cJSON.h"
elif [ -f "/usr/include/cjson/cjson.h" ]; then
    print_success "cJSON header found at /usr/include/cjson/cjson.h"
    cjson_header_found=true
    cjson_header_path="/usr/include/cjson/cjson.h"
elif [ -f "/usr/include/cjson.h" ]; then
    print_success "cJSON header found at /usr/include/cjson.h"
    cjson_header_found=true
    cjson_header_path="/usr/include/cjson.h"
elif [ -f "/usr/local/include/cjson/cJSON.h" ]; then
    print_success "cJSON header found at /usr/local/include/cjson/cJSON.h"
    cjson_header_found=true
    cjson_header_path="/usr/local/include/cjson/cJSON.h"
elif [ -f "/usr/local/include/cjson/cjson.h" ]; then
    print_success "cJSON header found at /usr/local/include/cjson/cjson.h"
    cjson_header_found=true
    cjson_header_path="/usr/local/include/cjson/cjson.h"
elif [ -f "/usr/local/include/cjson.h" ]; then
    print_success "cJSON header found at /usr/local/include/cjson.h"
    cjson_header_found=true
    cjson_header_path="/usr/local/include/cjson.h"
else
    # Try to find cJSON headers using find command (search for both cases)
    print_status "Searching for cJSON headers in system..."
    found_headers=$(find /usr/include /usr/local/include -name "*cjson*" -type f 2>/dev/null | grep -E "\.(h|hpp)$" | head -1)
    if [ -n "$found_headers" ]; then
        print_success "cJSON header found at: $found_headers"
        cjson_header_found=true
        cjson_header_path="$found_headers"
    fi
fi

if [ "$cjson_found" = false ]; then
    print_warning "cJSON library not found via standard methods"
fi

if [ "$cjson_header_found" = false ]; then
    print_error "cJSON header not found! Debugging..."
    
    # Show what packages are actually installed
    print_status "Checking installed cJSON packages:"
    dpkg -l | grep cjson
    
    # Show what files are in the cjson-dev package
    print_status "Files in libcjson-dev package:"
    dpkg -L libcjson-dev 2>/dev/null | grep -E "\.(h|hpp)$" | head -10
    
    # Try to find any cjson files
    print_status "Searching for any cjson files:"
    find /usr -name "*cjson*" -type f 2>/dev/null | head -10
    
    print_status "Trying to reinstall cJSON development package..."
    sudo apt install --reinstall -y libcjson-dev
    
    # Check again after reinstall
    print_status "Checking again after reinstall..."
    if find /usr/include /usr/local/include -name "cjson.h" -type f 2>/dev/null | head -1; then
        print_success "cJSON header found after reinstall!"
        cjson_header_found=true
    else
        print_error "cJSON header still not found after reinstall"
        print_status "Please run the script again after cJSON reinstallation"
        exit 1
    fi
fi

# Update library cache
print_status "Updating library cache..."
sudo ldconfig

# Compile the application
print_status "Cleaning previous build..."
make clean || true

print_status "Compiling EchoStream application with tone detection..."
make

# If compilation fails, try with explicit library paths
if [ $? -ne 0 ]; then
    print_warning "First compilation attempt failed, trying with explicit library paths..."
    
fi

if [ $? -eq 0 ]; then
    print_success "Compilation successful!"
    
    # Verify the executable was built
    if [ -f "./echostream" ]; then
        print_success "EchoStream executable created successfully!"
        
    else
        print_error "EchoStream executable not found after compilation!"
        exit 1
    fi
else
    print_error "Compilation failed!"
    print_error "Please check the error messages above and ensure all dependencies are installed."
    exit 1
fi

# Make executable
chmod +x ./echostream

# Create legacy symlink for backward compatibility
if [ -f "./echostream" ]; then
    ln -sf ./echostream ./api_call
    print_success "Created legacy symlink: api_call -> echostream"
fi

# Check for USB audio devices
print_status "Checking for USB audio devices..."
if lsusb | grep -iq audio; then
    print_success "USB audio devices found"
else
    print_warning "No USB audio devices detected"
fi

# Show audio devices
print_status "Available audio devices:"
if ! aplay -l 2>/dev/null; then
    print_warning "Could not list audio devices"
fi

# Check GPIO permissions
print_status "Checking GPIO permissions..."
if [ -w /sys/class/gpio/export ]; then
    print_success "GPIO permissions OK"
else
    print_warning "GPIO permissions may need adjustment"
    print_status "Adding user to gpio group..."
    sudo usermod -a -G gpio $USER
    print_warning "Please log out and log back in for GPIO permissions to take effect"
fi


# Auto-run EchoStream after installation
print_status "Starting EchoStream with tone detection..."
echo "Press Ctrl+C to stop"
echo ""
./echostream
