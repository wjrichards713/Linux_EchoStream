#!/bin/bash

# EchoStream Installation and Run Script for Raspberry Pi 5
# This script uses the comprehensive Makefile for installation

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

# Check if api_call.c exists
if [ ! -f "api_call.c" ]; then
    print_error "api_call.c not found in current directory!"
    print_error "Please ensure you're running this script from the EchoStream directory."
    exit 1
fi

print_status "Starting EchoStream installation using Makefile..."

# Use the comprehensive Makefile for installation
print_status "Installing dependencies and building application..."
make all

if [ $? -eq 0 ]; then
    print_success "Installation and build successful!"
else
    print_error "Installation failed!"
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
fi

# Check MQTT broker status
print_status "Checking MQTT broker status..."
if systemctl is-active --quiet mosquitto; then
    print_success "Mosquitto MQTT broker is running"
else
    print_warning "Mosquitto MQTT broker is not running"
    print_status "Starting Mosquitto broker..."
    sudo systemctl start mosquitto
fi

print_success "Installation complete!"
echo ""
echo "=========================================="
echo "EchoStream is ready to run!"
echo "=========================================="
echo ""
echo "Available commands:"
echo "  ./api_call        - Run the application"
echo "  make run          - Build and run"
echo "  make install      - Install to system"
echo "  make clean        - Clean build files"
echo "  make help         - Show all options"
echo ""
echo "To start the application:"
echo "  ./api_call"
echo ""
echo "To install as a system service:"
echo "  make install"
echo "  sudo systemctl start echostream.service"
echo ""