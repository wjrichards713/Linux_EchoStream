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
echo ""
echo "Usage examples:"
echo "  ./api_call                    # Run both channels with defaults"
echo "  ./api_call 555               # Run channel 555 with defaults"
echo "  ./api_call John PoliceDept   # Run both channels with custom names"
echo "  ./api_call John PoliceDept 555 # Run channel 555 with custom names"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Build and run using Makefile
make run
