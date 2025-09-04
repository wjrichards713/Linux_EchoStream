#!/bin/bash

echo "=== GPIO Permissions and Configuration Check ==="
echo

echo "1. Checking user groups:"
groups | grep -q gpio && echo "✅ User is in gpio group" || echo "❌ User is NOT in gpio group"
groups | grep -q audio && echo "✅ User is in audio group" || echo "❌ User is NOT in audio group"
echo

echo "2. Checking GPIO device permissions:"
ls -la /dev/gpiochip* 2>/dev/null || echo "No gpiochip devices found"
echo

echo "3. Checking GPIO export permissions:"
if [ -w /sys/class/gpio/export ]; then
    echo "✅ Can write to /sys/class/gpio/export"
else
    echo "❌ Cannot write to /sys/class/gpio/export"
fi
echo

echo "4. Testing GPIO pin access:"
echo "Testing pin 16 (GPIO 567):"
if echo "567" > /sys/class/gpio/export 2>/dev/null; then
    echo "✅ Pin 16 can be exported"
    echo "567" > /sys/class/gpio/unexport 2>/dev/null
else
    echo "❌ Pin 16 cannot be exported"
fi

echo "Testing pin 18 (GPIO 568):"
if echo "568" > /sys/class/gpio/export 2>/dev/null; then
    echo "✅ Pin 18 can be exported"
    echo "568" > /sys/class/gpio/unexport 2>/dev/null
else
    echo "❌ Pin 18 cannot be exported"
fi
echo

echo "5. Checking systemd service permissions:"
if systemctl is-active --quiet echostream; then
    echo "✅ EchoStream service is running"
    echo "Service user: $(systemctl show echostream --property=User --value)"
    echo "Service groups: $(systemctl show echostream --property=SupplementaryGroups --value)"
else
    echo "❌ EchoStream service is not running"
fi
echo

echo "6. Checking /boot/config.txt for GPIO settings:"
if [ -f /boot/config.txt ]; then
    if grep -q "dtparam=gpio=on" /boot/config.txt; then
        echo "✅ GPIO overlay is enabled in /boot/config.txt"
    else
        echo "⚠️  GPIO overlay not explicitly enabled (may be default)"
    fi
else
    echo "❌ /boot/config.txt not found"
fi
echo

echo "=== Check Complete ==="
