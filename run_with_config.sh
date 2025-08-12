#!/bin/bash

# EchoStream Run with Config Script
# This script reads the config file and runs EchoStream with the correct parameters

CONFIG_FILE="$HOME/.an/config.json"

echo "=========================================="
echo "EchoStream Run with Config"
echo "=========================================="

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found at $CONFIG_FILE"
    echo "Please ensure the AudioNode configuration is properly set up."
    exit 1
fi

# Function to extract values using Python (fallback when jq is not available)
extract_with_python() {
    python3 -c "
import json
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    
    software_config = config.get('shadow', {}).get('state', {}).get('desired', {}).get('software_configuration', [])
    
    if software_config:
        config_item = software_config[0]
        username = config_item.get('user_name', 'EchoStream')
        agency_name = config_item.get('agency_name', 'TestAgency')
        channel_one = config_item.get('channel_one', {}).get('channel_id', '555')
        channel_two = config_item.get('channel_two', {}).get('channel_id', '666')
    else:
        username = 'EchoStream'
        agency_name = 'TestAgency'
        channel_one = '555'
        channel_two = '666'
    
    print(f'USERNAME={username}')
    print(f'AGENCY_NAME={agency_name}')
    print(f'CHANNEL_ONE={channel_one}')
    print(f'CHANNEL_TWO={channel_two}')
    
except Exception as e:
    print('USERNAME=EchoStream')
    print('AGENCY_NAME=TestAgency')
    print('CHANNEL_ONE=555')
    print('CHANNEL_TWO=666')
    print(f'ERROR: {e}', file=sys.stderr)
"
}

# Extract values from config file
echo "Reading configuration from $CONFIG_FILE..."

# Try to use jq first, fallback to Python if not available
if command -v jq &> /dev/null; then
    echo "Using jq for JSON parsing..."
    # Extract username and agency_name from software_configuration
    USERNAME=$(jq -r '.shadow.state.desired.software_configuration[0].user_name' "$CONFIG_FILE" 2>/dev/null)
    AGENCY_NAME=$(jq -r '.shadow.state.desired.software_configuration[0].agency_name' "$CONFIG_FILE" 2>/dev/null)

    # Extract channel IDs
    CHANNEL_ONE=$(jq -r '.shadow.state.desired.software_configuration[0].channel_one.channel_id' "$CONFIG_FILE" 2>/dev/null)
    CHANNEL_TWO=$(jq -r '.shadow.state.desired.software_configuration[0].channel_two.channel_id' "$CONFIG_FILE" 2>/dev/null)
else
    echo "jq not available, using Python for JSON parsing..."
    # Use Python to extract values
    while IFS='=' read -r key value; do
        case $key in
            USERNAME) USERNAME="$value" ;;
            AGENCY_NAME) AGENCY_NAME="$value" ;;
            CHANNEL_ONE) CHANNEL_ONE="$value" ;;
            CHANNEL_TWO) CHANNEL_TWO="$value" ;;
        esac
    done < <(extract_with_python)
fi

# Check if values were extracted successfully
if [ "$USERNAME" = "null" ] || [ "$AGENCY_NAME" = "null" ] || [ -z "$USERNAME" ] || [ -z "$AGENCY_NAME" ]; then
    echo "WARNING: Could not extract username or agency_name from config, using defaults"
    USERNAME="EchoStream"
    AGENCY_NAME="TestAgency"
fi

if [ "$CHANNEL_ONE" = "null" ] || [ "$CHANNEL_TWO" = "null" ] || [ -z "$CHANNEL_ONE" ] || [ -z "$CHANNEL_TWO" ]; then
    echo "WARNING: Could not extract channel IDs from config, using defaults"
    CHANNEL_ONE="555"
    CHANNEL_TWO="666"
fi

echo "Configuration extracted:"
echo "  Username: $USERNAME"
echo "  Agency: $AGENCY_NAME"
echo "  Channel One: $CHANNEL_ONE"
echo "  Channel Two: $CHANNEL_TWO"
echo ""

# Determine which channels are available and set run mode
if [ "$CHANNEL_ONE" != "null" ] && [ "$CHANNEL_TWO" != "null" ] && [ "$CHANNEL_ONE" != "" ] && [ "$CHANNEL_TWO" != "" ]; then
    # Both channels are defined
    RUN_MODE="both"
    echo "Both channels defined, running in dual-channel mode"
elif [ "$CHANNEL_ONE" != "null" ] && [ "$CHANNEL_ONE" != "" ]; then
    # Only channel one is defined
    RUN_MODE="$CHANNEL_ONE"
    echo "Only channel one defined ($CHANNEL_ONE), running in single-channel mode"
elif [ "$CHANNEL_TWO" != "null" ] && [ "$CHANNEL_TWO" != "" ]; then
    # Only channel two is defined
    RUN_MODE="$CHANNEL_TWO"
    echo "Only channel two defined ($CHANNEL_TWO), running in single-channel mode"
else
    # No channels defined, use defaults
    RUN_MODE="both"
    echo "No channels defined, using default dual-channel mode"
fi

# Check if api_call executable exists
if [ ! -f "./api_call" ]; then
    echo "Building EchoStream application..."
    make api_call
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to build EchoStream application"
        exit 1
    fi
fi

echo "Starting EchoStream with configuration parameters..."
if [ "$RUN_MODE" = "both" ]; then
    echo "Command: ./api_call \"$USERNAME\" \"$AGENCY_NAME\" both"
    ./api_call "$USERNAME" "$AGENCY_NAME" both
else
    echo "Command: ./api_call \"$USERNAME\" \"$AGENCY_NAME\" $RUN_MODE"
    ./api_call "$USERNAME" "$AGENCY_NAME" "$RUN_MODE"
fi 