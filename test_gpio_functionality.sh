#!/bin/bash

echo "=== GPIO Functionality Test ==="
echo "This script will test GPIO pin reading functionality"
echo "Connect pins 16, 18, 38, 40 to GND to test activation"
echo "Press Ctrl+C to stop"
echo

# Test GPIO pin reading
test_gpio_pin() {
    local pin=$1
    local physical_pin=$2
    local channel=$3
    
    echo "Testing GPIO $pin (Physical Pin $physical_pin) for Channel $channel"
    
    # Read the pin value
    local value=$(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)
    if [ $? -eq 0 ]; then
        if [ "$value" = "0" ]; then
            echo "  ✅ Channel $channel: ACTIVE (PTT ON) - Pin connected to GND"
        else
            echo "  ⚪ Channel $channel: INACTIVE (PTT OFF) - Pin not connected to GND"
        fi
    else
        echo "  ❌ Channel $channel: ERROR - Cannot read GPIO $pin"
    fi
}

# Monitor GPIO pins
while true; do
    clear
    echo "=== GPIO Functionality Test ==="
    echo "Time: $(date)"
    echo "Connect pins to GND to test activation:"
    echo
    
    test_gpio_pin 567 16 "308e2478-072c-4d8b-ffff24d-51854e06711a"
    test_gpio_pin 568 18 "94415b61-8007-430d-ffffea0-10fc9fee2d8e"
    test_gpio_pin 589 38 "555"
    test_gpio_pin 590 40 "666"
    
    echo
    echo "Press Ctrl+C to stop monitoring"
    sleep 1
done
