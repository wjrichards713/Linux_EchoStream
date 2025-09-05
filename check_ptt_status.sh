#!/bin/bash

echo "=== PTT Status Check ==="
echo "Current time: $(date)"
echo

# Check if EchoStream service is running
echo "=== Service Status ==="
if systemctl is-active --quiet echostream; then
    echo "✅ EchoStream service: RUNNING"
else
    echo "❌ EchoStream service: NOT RUNNING"
fi

echo

# Check GPIO pins
echo "=== GPIO Pin Status ==="
for pin in 567 568 589 590; do
    if [ -f "/sys/class/gpio/gpio$pin/value" ]; then
        value=$(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)
        case $pin in
            567) channel="308e2478... (Pin 16)" ;;
            568) channel="94415b61... (Pin 18)" ;;
            589) channel="555 (Pin 38)" ;;
            590) channel="666 (Pin 40)" ;;
        esac
        
        if [ "$value" = "0" ]; then
            echo "🔴 $channel: ACTIVE (PTT ON)"
        else
            echo "⚪ $channel: INACTIVE (PTT OFF)"
        fi
    else
        echo "❌ GPIO $pin: Not available"
    fi
done

echo

# Check recent logs
echo "=== Recent PTT Activity ==="
journalctl -u echostream --since "1 minute ago" | grep -E "(GPIO STATE CHANGE|transmit_started|transmit_ended)" | tail -10

echo

# Check MQTT status
echo "=== MQTT Status ==="
if pgrep -f "mosquitto" > /dev/null; then
    echo "✅ MQTT broker: RUNNING"
else
    echo "❌ MQTT broker: NOT RUNNING"
fi
