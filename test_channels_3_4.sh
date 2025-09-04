#!/bin/bash

echo "=== Testing Channels 3 & 4 GPIO Pins ==="
echo "This will test if GPIO pins 567 and 568 are working"
echo

# Test GPIO pin 567 (Physical Pin 16 - Channel 3)
echo "Testing GPIO 567 (Physical Pin 16) for Channel 3..."
if [ -f "/sys/class/gpio/gpio567/value" ]; then
    value=$(cat /sys/class/gpio/gpio567/value)
    echo "  GPIO 567 value: $value"
    if [ "$value" = "0" ]; then
        echo "  ✅ Channel 3: ACTIVE (PTT ON)"
    else
        echo "  ⚪ Channel 3: INACTIVE (PTT OFF)"
    fi
else
    echo "  ❌ Channel 3: GPIO 567 not exported or accessible"
fi

echo

# Test GPIO pin 568 (Physical Pin 18 - Channel 4)
echo "Testing GPIO 568 (Physical Pin 18) for Channel 4..."
if [ -f "/sys/class/gpio/gpio568/value" ]; then
    value=$(cat /sys/class/gpio/gpio568/value)
    echo "  GPIO 568 value: $value"
    if [ "$value" = "0" ]; then
        echo "  ✅ Channel 4: ACTIVE (PTT ON)"
    else
        echo "  ⚪ Channel 4: INACTIVE (PTT OFF)"
    fi
else
    echo "  ❌ Channel 4: GPIO 568 not exported or accessible"
fi

echo
echo "=== Checking GPIO Export Status ==="
ls -la /sys/class/gpio/gpio567* 2>/dev/null || echo "GPIO 567 not found"
ls -la /sys/class/gpio/gpio568* 2>/dev/null || echo "GPIO 568 not found"

echo
echo "=== Testing pinctrl Commands ==="
echo "Testing pinctrl for GPIO 567 (Physical Pin 16):"
pinctrl set gpiochip4 0 ip pu
echo "Exit code: $?"

echo "Testing pinctrl for GPIO 568 (Physical Pin 18):"
pinctrl set gpiochip4 1 ip pu
echo "Exit code: $?"

echo
echo "=== Manual GPIO Export Test ==="
echo "Trying to manually export GPIO 567:"
echo "567" > /sys/class/gpio/export 2>&1
echo "Exit code: $?"

echo "Trying to manually export GPIO 568:"
echo "568" > /sys/class/gpio/export 2>&1
echo "Exit code: $?"

echo
echo "=== Final Status ==="
if [ -f "/sys/class/gpio/gpio567/value" ]; then
    echo "GPIO 567: Available"
    cat /sys/class/gpio/gpio567/value
else
    echo "GPIO 567: Not available"
fi

if [ -f "/sys/class/gpio/gpio568/value" ]; then
    echo "GPIO 568: Available"
    cat /sys/class/gpio/gpio568/value
else
    echo "GPIO 568: Not available"
fi
