#!/bin/bash

# EchoStream Tone Detection Installation Script
# This script installs the necessary dependencies and builds the tone detection system

echo "=== EchoStream Tone Detection Installation ==="
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Please do not run this script as root. It will use sudo when needed."
    exit 1
fi

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install required dependencies
echo "Installing dependencies..."
sudo apt-get install -y \
    libportaudio2-dev \
    libopus-dev \
    libcurl4-openssl-dev \
    libwebsockets-dev \
    libfftw3-dev \
    libcjson-dev \
    libssl-dev \
    libcrypto++-dev \
    libgpiod-dev \
    build-essential \
    pkg-config

# Check if installation was successful
if [ $? -eq 0 ]; then
    echo "Dependencies installed successfully!"
else
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

# Build the project
echo "Building EchoStream with tone detection..."
make clean
make

if [ $? -eq 0 ]; then
    echo "Build successful!"
else
    echo "ERROR: Build failed"
    exit 1
fi

# Build and run test
echo "Building and running tone detection test..."
make test

if [ $? -eq 0 ]; then
    echo "Test build successful!"
    echo "Running tone detection test..."
    ./test_tone_detect
    if [ $? -eq 0 ]; then
        echo "Test passed successfully!"
    else
        echo "WARNING: Test failed, but build was successful"
    fi
else
    echo "WARNING: Test build failed"
fi

echo
echo "=== Installation Complete ==="
echo
echo "To run EchoStream with tone detection:"
echo "  ./echostream"
echo
echo "To run just the tone detection test:"
echo "  ./test_tone_detect"
echo
echo "Configuration file should be placed at:"
echo "  /home/will/.an/config.json"
echo
echo "For more information, see TONE_DETECTION_README.md"
