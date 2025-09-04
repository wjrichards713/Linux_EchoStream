#!/bin/bash

echo "=== Testing EchoStream Fixes ==="
echo "1. Cleaning previous build..."
make clean

echo "2. Building with fixes..."
make api_call

if [ $? -eq 0 ]; then
    echo "✅ Build successful - no compilation errors"
else
    echo "❌ Build failed - compilation errors present"
    exit 1
fi

echo "3. Testing GPIO configuration..."
echo "Testing pinctrl command for gpiochip4..."
pinctrl set gpiochip4 20 ip pu

if [ $? -eq 0 ]; then
    echo "✅ GPIO pinctrl command works"
else
    echo "❌ GPIO pinctrl command failed"
fi

echo "4. Checking available audio devices..."
aplay -l 2>/dev/null | grep -i usb || echo "No USB audio devices found"

echo "5. Testing PortAudio device enumeration..."
echo "Running audio device test..."
./api_call --test-audio 2>&1 | head -20 || echo "Audio test not available"

echo "=== Test Complete ==="
