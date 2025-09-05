#!/bin/bash

echo "=== Diagnosing Channels 3 & 4 GPIO Issue ==="
echo "Time: $(date)"
echo

# Check if EchoStream is running
echo "=== Service Status ==="
if systemctl is-active --quiet echostream; then
    echo "✅ EchoStream service: RUNNING"
    echo "Process ID: $(pgrep -f api_call)"
else
    echo "❌ EchoStream service: NOT RUNNING"
    exit 1
fi

echo

# Check GPIO export status
echo "=== GPIO Export Status ==="
for pin in 567 568 589 590; do
    if [ -f "/sys/class/gpio/gpio$pin/value" ]; then
        value=$(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)
        case $pin in
            567) channel="Channel 3 (308e2478...)" ;;
            568) channel="Channel 4 (94415b61...)" ;;
            589) channel="Channel 1 (555)" ;;
            590) channel="Channel 2 (666)" ;;
        esac
        echo "✅ GPIO $pin ($channel): Exported, Value=$value"
    else
        case $pin in
            567) channel="Channel 3 (308e2478...)" ;;
            568) channel="Channel 4 (94415b61...)" ;;
            589) channel="Channel 1 (555)" ;;
            590) channel="Channel 2 (666)" ;;
        esac
        echo "❌ GPIO $pin ($channel): NOT EXPORTED"
    fi
done

echo

# Check pinctrl status
echo "=== Pinctrl Status ==="
echo "Testing pinctrl for Channel 3 (GPIO 567, Physical Pin 16):"
pinctrl set gpiochip4 0 ip pu
echo "Exit code: $?"

echo "Testing pinctrl for Channel 4 (GPIO 568, Physical Pin 18):"
pinctrl set gpiochip4 1 ip pu
echo "Exit code: $?"

echo

# Check if we can manually export the pins
echo "=== Manual GPIO Export Test ==="
echo "Trying to export GPIO 567 (Channel 3):"
echo "567" > /sys/class/gpio/export 2>&1
echo "Exit code: $?"

echo "Trying to export GPIO 568 (Channel 4):"
echo "568" > /sys/class/gpio/export 2>&1
echo "Exit code: $?"

echo

# Check current GPIO values after manual export
echo "=== Current GPIO Values ==="
for pin in 567 568 589 590; do
    if [ -f "/sys/class/gpio/gpio$pin/value" ]; then
        value=$(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)
        case $pin in
            567) channel="Channel 3" ;;
            568) channel="Channel 4" ;;
            589) channel="Channel 1" ;;
            590) channel="Channel 2" ;;
        esac
        echo "$channel (GPIO $pin): $value"
    else
        case $pin in
            567) channel="Channel 3" ;;
            568) channel="Channel 4" ;;
            589) channel="Channel 1" ;;
            590) channel="Channel 2" ;;
        esac
        echo "$channel (GPIO $pin): NOT AVAILABLE"
    fi
done

echo

# Check recent EchoStream logs for GPIO initialization
echo "=== Recent EchoStream GPIO Logs ==="
journalctl -u echostream --since "10 minutes ago" | grep -E "(GPIO|pinctrl|init_gpio|Failed|ERROR|WARNING)" | tail -15

echo

# Check if the application is actually monitoring GPIO
echo "=== GPIO Monitoring Status ==="
if pgrep -f "api_call" > /dev/null; then
    echo "✅ EchoStream process is running"
    echo "Process details:"
    ps aux | grep api_call | grep -v grep
else
    echo "❌ EchoStream process not found"
fi
