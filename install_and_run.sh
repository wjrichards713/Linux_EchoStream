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

# Install FFTW library for tone detection
print_status "Installing FFTW library for tone detection..."
sudo apt install -y libfftw3-dev libfftw3-double3 libfftw3-single3

# Verify FFTW installation
print_status "Verifying FFTW installation..."
if make test-fftw >/dev/null 2>&1; then
    print_success "FFTW library installed and working correctly"
else
    print_error "FFTW library installation failed or not working"
    print_status "Trying to find available FFTW packages..."
    apt search libfftw3 | grep -E "libfftw3.*dev|libfftw3.*3"
    print_error "Please install the correct FFTW packages manually and try again."
    exit 1
fi

# Check if api_call.c exists
if [ ! -f "api_call.c" ]; then
    print_error "api_call.c not found in current directory!"
    print_error "Please ensure you're running this script from the EchoStream directory."
    exit 1
fi

print_success "All dependencies installed successfully!"

# Compile the application
print_status "Cleaning previous build..."
make clean || true

print_status "Compiling EchoStream application..."
make

if [ $? -eq 0 ]; then
    print_success "Compilation successful!"
else
    print_error "Compilation failed!"
    exit 1
fi

# Make executable
chmod +x ./api_call

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
print_status "Starting EchoStream automatically..."
echo "Press Ctrl+C to stop"
echo ""
./api_call
