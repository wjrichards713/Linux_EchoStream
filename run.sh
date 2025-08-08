#!/bin/bash

# EchoStream Quick Run Script
# This script builds and runs the EchoStream application

echo "=========================================="
echo "EchoStream Quick Run"
echo "=========================================="

# Check if api_call.c exists
if [ ! -f "api_call.c" ]; then
    echo "ERROR: api_call.c not found in current directory!"
    echo "Please run this script from the EchoStream directory."
    exit 1
fi

echo "Building and running EchoStream application..."
echo "Press Ctrl+C to stop"
echo ""

# Build and run using Makefile
make run
