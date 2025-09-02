#!/bin/bash

# EchoStream Run with Config Script
# This script reads the config file and runs EchoStream with the correct parameters

CONFIG_FILE="$HOME/.an/config.json"

# Function to handle shutdown signals
cleanup() {
    echo "Received shutdown signal, cleaning up..."
    if [ ! -z "$API_CALL_PID" ]; then
        echo "Stopping api_call process (PID: $API_CALL_PID)..."
        kill -TERM $API_CALL_PID 2>/dev/null
        wait $API_CALL_PID 2>/dev/null
    fi
    echo "Cleanup complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

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
        
        # Extract all channels dynamically
        channels = []
        
        # Check for channel_one, channel_two, channel_three, channel_four, etc.
        channel_index = 1
        while True:
            channel_key = f'channel_{channel_index}' if channel_index > 2 else ('channel_one' if channel_index == 1 else 'channel_two')
            channel_data = config_item.get(channel_key, {})
            
            if channel_data and 'channel_id' in channel_data:
                channels.append(channel_data['channel_id'])
                channel_index += 1
            else:
                break
        
        # If no channels found, use defaults
        if not channels:
            channels = ['555', '666']
    else:
        username = 'EchoStream'
        agency_name = 'TestAgency'
        channels = ['555', '666']
    
    print(f'USERNAME={username}')
    print(f'AGENCY_NAME={agency_name}')
    print(f'CHANNELS={",".join(channels)}')
    
except Exception as e:
    print('USERNAME=EchoStream')
    print('AGENCY_NAME=TestAgency')
    print('CHANNELS=555,666')
    print(f'ERROR: {e}', file=sys.stderr)
"
}

# Extract values from config file
# Try to use jq first, fallback to Python if not available
if command -v jq &> /dev/null; then
    # Extract username and agency_name from software_configuration
    USERNAME=$(jq -r '.shadow.state.desired.software_configuration[0].user_name' "$CONFIG_FILE" 2>/dev/null)
    AGENCY_NAME=$(jq -r '.shadow.state.desired.software_configuration[0].agency_name' "$CONFIG_FILE" 2>/dev/null)

    # Extract all channels dynamically using jq
    CHANNELS=$(jq -r '.shadow.state.desired.software_configuration[0] | 
        [.channel_one.channel_id, .channel_two.channel_id, .channel_three.channel_id, .channel_four.channel_id] | 
        map(select(. != null and . != "")) | join(",")' "$CONFIG_FILE" 2>/dev/null)
else
    # Use Python to extract values
    while IFS='=' read -r key value; do
        case $key in
            USERNAME) USERNAME="$value" ;;
            AGENCY_NAME) AGENCY_NAME="$value" ;;
            CHANNELS) CHANNELS="$value" ;;
        esac
    done < <(extract_with_python)
fi

# Check if values were extracted successfully
if [ "$USERNAME" = "null" ] || [ "$AGENCY_NAME" = "null" ] || [ -z "$USERNAME" ] || [ -z "$AGENCY_NAME" ]; then
    echo "WARNING: Could not extract username or agency_name from config, using defaults"
    USERNAME="EchoStream"
    AGENCY_NAME="TestAgency"
fi

if [ "$CHANNELS" = "null" ] || [ -z "$CHANNELS" ]; then
    echo "WARNING: Could not extract channel IDs from config, using defaults"
    CHANNELS="555,666"
fi

# Display extracted configuration
echo "Configuration extracted:"
echo "  Username: $USERNAME"
echo "  Agency: $AGENCY_NAME"
echo "  Channels: $CHANNELS"

# Convert comma-separated channels to space-separated for passing to C program
CHANNEL_ARGS=$(echo "$CHANNELS" | tr ',' ' ')

# Check if api_call executable exists
if [ ! -f "./api_call" ]; then
    echo "Building EchoStream application..."
    make api_call
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to build EchoStream application"
        exit 1
    fi
fi

# Start EchoStream with configuration parameters
echo "Executing: ./api_call \"$USERNAME\" \"$AGENCY_NAME\" $CHANNEL_ARGS"
./api_call "$USERNAME" "$AGENCY_NAME" $CHANNEL_ARGS &

# Store the PID of the api_call process
API_CALL_PID=$!

# Wait for the api_call process to complete
wait $API_CALL_PID
EXIT_CODE=$?

exit $EXIT_CODE 