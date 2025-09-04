#!/bin/bash

echo "=== Verifying GPIO Pin Usage by EchoStream ==="
echo

echo "1. Checking if GPIO pins are already exported:"
for pin in 567 568 589 590; do
    if [ -d "/sys/class/gpio/gpio$pin" ]; then
        echo "✅ GPIO $pin is already exported (in use by EchoStream)"
        echo "   Current value: $(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)"
        echo "   Direction: $(cat /sys/class/gpio/gpio$pin/direction 2>/dev/null)"
    else
        echo "❌ GPIO $pin is not exported"
    fi
done
echo

echo "2. Checking EchoStream process:"
if pgrep -f "api_call" > /dev/null; then
    echo "✅ EchoStream application is running (PID: $(pgrep -f api_call))"
else
    echo "❌ EchoStream application is not running"
fi
echo

echo "3. Checking GPIO usage in logs:"
echo "Recent GPIO activity:"
journalctl -u echostream --since "5 minutes ago" | grep -E "(GPIO|pin)" | tail -10
echo

echo "4. Testing GPIO reading (should work even if exported):"
for pin in 567 568 589 590; do
    if [ -f "/sys/class/gpio/gpio$pin/value" ]; then
        value=$(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)
        echo "GPIO $pin value: $value"
    fi
done
echo

echo "=== Verification Complete ==="
