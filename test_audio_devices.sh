#!/bin/bash

echo "=========================================="
echo "Audio Device Diagnostic Script"
echo "=========================================="

echo "1. Listing all ALSA devices:"
aplay -l

echo ""
echo "2. Testing each USB device individually:"

# Test each USB device
for i in {2..5}; do
    echo "Testing device hw:$i,0..."
    
    # Test input (mono)
    echo "  - Testing input mono (5 seconds)..."
    timeout 5s arecord -D hw:$i,0 -f cd -c 1 -d 5 test_input_$i.wav 2>&1 | head -5
    
    # Test input (stereo) - this might fail for mono devices
    echo "  - Testing input stereo (5 seconds)..."
    timeout 5s arecord -D hw:$i,0 -f cd -c 2 -d 5 test_input_stereo_$i.wav 2>&1 | head -5
    
    # Test output
    echo "  - Testing output..."
    if [ -f test_input_$i.wav ]; then
        timeout 3s aplay -D hw:$i,0 test_input_$i.wav 2>&1 | head -5
        rm -f test_input_$i.wav
    else
        echo "    (No input file to test output)"
    fi
    
    echo "  - Testing full-duplex (simultaneous input/output)..."
    timeout 3s bash -c "arecord -D hw:$i,0 -f cd -d 2 test_duplex_$i.wav & aplay -D hw:$i,0 test_duplex_$i.wav" 2>&1 | head -5
    rm -f test_duplex_$i.wav
    
    echo ""
done

echo "3. Checking for device conflicts:"
lsof /dev/snd/* 2>/dev/null || echo "No devices currently in use"

echo ""
echo "4. ALSA configuration test:"
alsactl store 2>/dev/null || echo "ALSA configuration check completed"

echo ""
echo "=========================================="
echo "Diagnostic complete!"
echo "=========================================="
