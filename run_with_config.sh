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

# Check if jq is available for JSON parsing
if ! command -v jq &> /dev/null; then
    echo "ERROR: jq is required for JSON parsing but not installed."
    echo "Please install jq: sudo apt install jq"
    exit 1
fi

# Extract values from config file
echo "Reading configuration from $CONFIG_FILE..."

# Extract username and agency_name from software_configuration
USERNAME=$(jq -r '.shadow.state.desired.software_configuration[0].user_name' "$CONFIG_FILE" 2>/dev/null)
AGENCY_NAME=$(jq -r '.shadow.state.desired.software_configuration[0].agency_name' "$CONFIG_FILE" 2>/dev/null)

# Extract channel IDs
CHANNEL_ONE=$(jq -r '.shadow.state.desired.software_configuration[0].channel_one.channel_id' "$CONFIG_FILE" 2>/dev/null)
CHANNEL_TWO=$(jq -r '.shadow.state.desired.software_configuration[0].channel_two.channel_id' "$CONFIG_FILE" 2>/dev/null)

# Check if values were extracted successfully
if [ "$USERNAME" = "null" ] || [ "$AGENCY_NAME" = "null" ]; then
    echo "WARNING: Could not extract username or agency_name from config, using defaults"
    USERNAME="EchoStream"
    AGENCY_NAME="TestAgency"
fi

if [ "$CHANNEL_ONE" = "null" ] || [ "$CHANNEL_TWO" = "null" ]; then
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