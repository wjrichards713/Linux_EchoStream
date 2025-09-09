#!/bin/bash

echo "=== Remote Audio Testing Script ==="
echo "Testing audio capture and processing on RPi..."

# Test 1: Check if audio devices are accessible
echo "1. Testing USB audio device access..."
for i in {2..5}; do
    echo "Testing hw:$i,0..."
    if timeout 2s arecord -D hw:$i,0 -f cd -c 1 -d 1 /tmp/test_$i.wav 2>/dev/null; then
        echo "  ✅ hw:$i,0 - Audio capture working"
        ls -la /tmp/test_$i.wav 2>/dev/null
    else
        echo "  ❌ hw:$i,0 - Audio capture failed"
    fi
done

# Test 2: Check PortAudio device status
echo -e "\n2. Testing PortAudio device capabilities..."
cat > /tmp/test_portaudio.c << 'EOF'
#include <portaudio.h>
#include <stdio.h>

int main() {
    Pa_Initialize();
    int numDevices = Pa_GetDeviceCount();
    printf("Total PortAudio devices: %d\n", numDevices);
    
    for (int i = 0; i < numDevices; i++) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(i);
        if (info && (strstr(info->name, "USB") || strstr(info->name, "usb"))) {
            printf("Device %d: %s\n", i, info->name);
            printf("  Input channels: %d, Output channels: %d\n", 
                   info->maxInputChannels, info->maxOutputChannels);
        }
    }
    Pa_Terminate();
    return 0;
}
EOF

gcc -o /tmp/test_portaudio /tmp/test_portaudio.c -lportaudio 2>/dev/null
if [ -f /tmp/test_portaudio ]; then
    /tmp/test_portaudio
    rm -f /tmp/test_portaudio /tmp/test_portaudio.c
fi

# Test 3: Check if our application is processing audio
echo -e "\n3. Checking application audio processing..."
if pgrep -f api_call > /dev/null; then
    echo "✅ api_call process is running"
    echo "Process info:"
    ps aux | grep api_call | grep -v grep
else
    echo "❌ api_call process not found"
fi

# Test 4: Check WebSocket connection
echo -e "\n4. Checking WebSocket connectivity..."
if netstat -an | grep -q ":443.*ESTABLISHED"; then
    echo "✅ WebSocket connection to server is active"
else
    echo "❌ No WebSocket connection found"
fi

# Test 5: Check UDP connection
echo -e "\n5. Checking UDP connection..."
if netstat -an | grep -q "35.90.120.85"; then
    echo "✅ UDP connection to server is active"
else
    echo "❌ No UDP connection found"
fi

echo -e "\n=== Test Complete ==="
