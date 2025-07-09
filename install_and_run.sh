#!/bin/bash

# EchoStream Installation and Run Script for Raspberry Pi 5
# This script installs all dependencies and runs the EchoStream audio application

set -e  # Exit on any error

echo "=========================================="
echo "EchoStream Installation Script for RPi 5"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Raspberry Pi
print_status "Checking if running on Raspberry Pi..."
if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
    print_warning "This script is designed for Raspberry Pi. Continuing anyway..."
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as regular user."
   exit 1
fi

# Update package manager
print_status "Updating package manager..."
sudo apt update -y

print_status "Upgrading system packages..."
sudo apt upgrade -y

# Install essential build tools
print_status "Installing build essentials..."
sudo apt install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    wget \
    curl

# Install audio dependencies
print_status "Installing audio libraries..."
sudo apt install -y \
    libportaudio2 \
    libportaudiocpp0 \
    portaudio19-dev \
    alsa-utils \
    pulseaudio \
    pulseaudio-utils

# Install Opus codec
print_status "Installing Opus codec..."
sudo apt install -y \
    libopus-dev \
    libopus0

# Install OpenSSL for encryption
print_status "Installing OpenSSL..."
sudo apt install -y \
    libssl-dev \
    openssl

# Install JSON-C library
print_status "Installing JSON-C library..."
sudo apt install -y \
    libjson-c-dev \
    libjson-c5

# Install cURL library
print_status "Installing cURL library..."
sudo apt install -y \
    libcurl4-openssl-dev \
    curl

# Install WebSockets library
print_status "Installing WebSockets library..."
sudo apt install -y \
    libwebsockets-dev

# Install pthread library (usually included with build-essential)
print_status "Ensuring pthread support..."
sudo apt install -y \
    libc6-dev

# Install pinctrl for GPIO control on RPi 5
print_status "Installing GPIO utilities for RPi 5..."
sudo apt install -y \
    raspi-gpio \
    gpiod \
    libgpiod-dev

# Check if api_call.c exists
if [ ! -f "api_call.c" ]; then
    print_error "api_call.c not found in current directory!"
    print_error "Please ensure you're running this script from the EchoStream directory."
    exit 1
fi

print_success "All dependencies installed successfully!"

# Compile the application
print_status "Compiling EchoStream application..."
gcc -Wall -Wextra -std=c99 -D_GNU_SOURCE -o api_call api_call.c \
    $(pkg-config --cflags --libs libcurl json-c libwebsockets portaudio-2.0 opus openssl) \
    -lpthread

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
lsusb | grep -i audio && print_success "USB audio devices found" || print_warning "No USB audio devices detected"

# Show audio devices
print_status "Available audio devices:"
aplay -l 2>/dev/null || print_warning "Could not list audio devices"

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

# Create systemd service file (optional)
print_status "Creating systemd service file..."
cat > echostream.service << EOF
[Unit]
Description=EchoStream Audio Communication
After=network.target sound.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/api_call
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

print_success "Service file created: echostream.service"
print_status "To install as system service, run: sudo cp echostream.service /etc/systemd/system/"

# Display usage information
echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Usage:"
echo "  Run both channels: ./api_call"
echo "  Run channel 555:  ./api_call 555"
echo "  Run channel 666:  ./api_call 666"
echo ""
echo "GPIO Connections:"
echo "  Pin 38 (GPIO 20) - Channel 555 PTT (connect to GND to transmit)"
echo "  Pin 40 (GPIO 21) - Channel 666 PTT (connect to GND to transmit)"
echo ""
echo "Audio Devices:"
echo "  Channel 555 - First USB audio device"
echo "  Channel 666 - Second USB audio device"
echo ""

# Ask user if they want to run now
echo -n "Do you want to run EchoStream now? (y/n): "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    print_status "Starting EchoStream..."
    echo "Press Ctrl+C to stop"
    echo ""
    ./api_call
else
    print_success "EchoStream is ready to run!"
    print_status "Run './api_call' when you're ready to start"
fi