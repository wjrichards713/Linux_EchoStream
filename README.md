# EchoStream - Audio Communication System

EchoStream is a real-time audio communication system designed for Raspberry Pi with MQTT integration for monitoring and control.

## Features

- **Real-time Audio Streaming**: Opus codec with AES-256-GCM encryption
- **Dual Channel Support**: Independent audio channels (555 and 666)
- **GPIO PTT Control**: Push-to-talk functionality via GPIO pins
- **MQTT Integration**: Real-time monitoring and status reporting
- **WebSocket Communication**: Remote control and configuration
- **UDP Audio Transport**: Low-latency audio streaming

## Quick Start

### One-Command Installation

```bash
# Complete installation and build
make all
```

### Run the Application

```bash
# Build and run
make run

# Or run directly
./api_call
```

## Project Structure

```
EchoStream/
├── api_call.c          # Main application source
├── Makefile            # Complete build system
├── echostream.service  # Systemd service file
├── install_and_run.sh  # Installation script
├── run.sh             # Quick run script
└── gpio_test.c        # GPIO testing utility
```

## Makefile Commands

```bash
make all          # Install dependencies and build everything
make install-deps  # Install all system dependencies
make build        # Build the application
make run          # Build and run the application
make install      # Install to system (/usr/local/bin)
make clean        # Clean build artifacts
make help         # Show all available options
```

## MQTT Topics

The application publishes to these MQTT topics:

- `echostream/audio/status` - Audio transmission status
- `echostream/gpio/status` - GPIO pin state changes
- `echostream/system/status` - System connection status
- `echostream/commands` - Command messages

## GPIO Configuration

- **Pin 38 (GPIO 20)** - Channel 555 PTT (connect to GND to transmit)
- **Pin 40 (GPIO 21)** - Channel 666 PTT (connect to GND to transmit)

## Audio Devices

The application automatically detects and assigns USB audio devices:
- Channel 555 uses the first USB audio device
- Channel 666 uses the second USB audio device

## System Service

To install as a system service:

```bash
make install
sudo systemctl start echostream.service
sudo systemctl enable echostream.service
```

## Dependencies

The Makefile automatically installs all required dependencies:
- PortAudio (audio I/O)
- Opus (audio codec)
- OpenSSL (encryption)
- cURL (HTTP client)
- JSON-C (JSON parsing)
- WebSockets (real-time communication)
- MQTT Paho (MQTT client)
- Mosquitto (MQTT broker)

## Troubleshooting

### Common Issues

1. **Audio not working**: Check USB audio device connections
2. **GPIO not responding**: Ensure proper GPIO permissions
3. **MQTT connection failed**: Verify Mosquitto broker is running
4. **Compilation errors**: Run `make clean` and `make all`

### Debug Information

The application provides detailed debug output for all operations. Check the console output for status messages and error information.

## License

This project is part of the EchoStream audio communication system. 