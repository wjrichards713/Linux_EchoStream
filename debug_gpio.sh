#!/bin/bash

echo "=== GPIO Debug Script for Raspberry Pi 5 ==="
echo

echo "1. Checking available GPIO chips..."
ls -la /dev/gpiochip* 2>/dev/null || echo "No gpiochip devices found"
echo

echo "2. Checking gpioinfo output..."
gpioinfo 2>/dev/null | head -30 || echo "gpioinfo not available"
echo

echo "3. Testing pinctrl commands..."
echo "Testing gpiochip4 line 20 (should be physical pin 38):"
pinctrl set gpiochip4 20 ip pu
echo "Exit code: $?"
echo

echo "Testing alternative syntax:"
pinctrl set 20 ip pu
echo "Exit code: $?"
echo

echo "4. Checking pinctrl help..."
pinctrl --help 2>/dev/null | head -10 || echo "pinctrl help not available"
echo

echo "5. Checking GPIO permissions..."
groups | grep -q gpio && echo "User is in gpio group" || echo "User is NOT in gpio group"
echo

echo "6. Testing with sudo..."
sudo pinctrl set gpiochip4 20 ip pu
echo "Sudo exit code: $?"
echo

echo "=== Debug Complete ==="
