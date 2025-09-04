#!/bin/bash

echo "=== Real-Time PTT Status Monitor ==="
echo "Monitoring all 4 channels for PTT button presses"
echo "Press Ctrl+C to stop"
echo

# Colors for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check GPIO pin status
check_gpio() {
    local pin=$1
    local channel=$2
    local physical_pin=$3
    
    if [ -f "/sys/class/gpio/gpio$pin/value" ]; then
        local value=$(cat /sys/class/gpio/gpio$pin/value 2>/dev/null)
        if [ "$value" = "0" ]; then
            echo -e "${RED}🔴 Channel $channel (Pin $physical_pin): ACTIVE (PTT ON)${NC}"
            return 0
        else
            echo -e "${GREEN}⚪ Channel $channel (Pin $physical_pin): INACTIVE (PTT OFF)${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠️  Channel $channel (Pin $physical_pin): GPIO $pin not available${NC}"
        return 2
    fi
}

# Function to check if GPIO pins are exported
check_gpio_export() {
    echo -e "${BLUE}=== GPIO Export Status ===${NC}"
    for pin in 567 568 589 590; do
        if [ -f "/sys/class/gpio/gpio$pin/value" ]; then
            echo -e "${GREEN}✅ GPIO $pin: Exported${NC}"
        else
            echo -e "${RED}❌ GPIO $pin: Not exported${NC}"
        fi
    done
    echo
}

# Initial check
check_gpio_export

# Monitor loop
while true; do
    clear
    echo -e "${BLUE}=== Real-Time PTT Status Monitor ===${NC}"
    echo "Time: $(date '+%H:%M:%S')"
    echo
    
    # Check each channel
    check_gpio 567 "308e2478..." "16"
    check_gpio 568 "94415b61..." "18" 
    check_gpio 589 "555" "38"
    check_gpio 590 "666" "40"
    
    echo
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    
    sleep 0.5
done
