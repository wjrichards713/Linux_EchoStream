CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE
LIBS = -lcurl -ljson-c -lwebsockets -lportaudio -lopus -lssl -lcrypto -lpthread -lpaho-mqtt3c

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
RED = \033[0;31m
NC = \033[0m # No Color

# Default target
all: check-deps install-deps build

# Check if running on Linux/Raspberry Pi
check-os:
	@echo "$(BLUE)[INFO]$(NC) Checking operating system..."
	@if [ "$(OS)" = "Windows_NT" ]; then \
		echo "$(RED)[ERROR]$(NC) This project is designed for Linux/Raspberry Pi"; \
		echo "$(YELLOW)[WARNING]$(NC) Some features may not work on Windows"; \
	else \
		echo "$(GREEN)[SUCCESS]$(NC) Linux/Raspberry Pi detected"; \
	fi

# Check if running as root
check-root:
	@echo "$(BLUE)[INFO]$(NC) Checking user permissions..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo "$(RED)[ERROR]$(NC) This script should not be run as root"; \
		echo "$(YELLOW)[INFO]$(NC) Please run as regular user"; \
		exit 1; \
	else \
		echo "$(GREEN)[SUCCESS]$(NC) Running as regular user"; \
	fi

# Update package manager
update-packages:
	@echo "$(BLUE)[INFO]$(NC) Updating package manager..."
	@sudo apt update -y

# Install system dependencies
install-system-deps:
	@echo "$(BLUE)[INFO]$(NC) Installing system dependencies..."
	@sudo apt install -y \
		build-essential \
		cmake \
		git \
		pkg-config \
		wget \
		curl \
		libssl-dev \
		doxygen \
		graphviz \
		raspi-gpio \
		gpiod \
		libgpiod-dev

# Install audio dependencies
install-audio-deps:
	@echo "$(BLUE)[INFO]$(NC) Installing audio libraries..."
	@sudo apt install -y \
		libportaudio2 \
		libportaudiocpp0 \
		portaudio19-dev \
		alsa-utils \
		pulseaudio \
		pulseaudio-utils

# Install codec and crypto dependencies
install-codec-deps:
	@echo "$(BLUE)[INFO]$(NC) Installing codec and crypto libraries..."
	@sudo apt install -y \
		libopus-dev \
		libopus0 \
		libssl-dev \
		openssl

# Install networking dependencies
install-networking-deps:
	@echo "$(BLUE)[INFO]$(NC) Installing networking libraries..."
	@sudo apt install -y \
		libjson-c-dev \
		libjson-c5 \
		libcurl4-openssl-dev \
		curl \
		libwebsockets-dev

# Install MQTT broker
install-mqtt-broker:
	@echo "$(BLUE)[INFO]$(NC) Installing Mosquitto MQTT broker..."
	@sudo apt install -y mosquitto mosquitto-clients
	@sudo systemctl start mosquitto
	@sudo systemctl enable mosquitto
	@if systemctl is-active --quiet mosquitto; then \
		echo "$(GREEN)[SUCCESS]$(NC) Mosquitto broker is running"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Mosquitto broker is not running"; \
	fi

# Install MQTT Paho library
install-mqtt-library:
	@echo "$(BLUE)[INFO]$(NC) Installing MQTT Paho library..."
	@if [ ! -d "paho.mqtt.c" ]; then \
		echo "$(BLUE)[INFO]$(NC) Cloning Paho MQTT C library..."; \
		git clone https://github.com/eclipse/paho.mqtt.c.git; \
	else \
		echo "$(BLUE)[INFO]$(NC) Paho MQTT C directory exists, updating..."; \
		cd paho.mqtt.c && git pull && cd ..; \
	fi
	@cd paho.mqtt.c && make clean && make && sudo make install
	@sudo ldconfig
	@echo "$(GREEN)[SUCCESS]$(NC) MQTT Paho library installed"

# Test MQTT installation
test-mqtt:
	@echo "$(BLUE)[INFO]$(NC) Testing MQTT library installation..."
	@if pkg-config --exists paho-mqtt3c; then \
		echo "$(GREEN)[SUCCESS]$(NC) MQTT library found by pkg-config"; \
		echo "Library version: $$(pkg-config --modversion paho-mqtt3c)"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) MQTT library not found by pkg-config"; \
	fi
	@echo "$(BLUE)[INFO]$(NC) Testing MQTT compilation..."
	@cat > test_mqtt.c << 'EOF' \
#include <stdio.h> \
#include <MQTTClient.h> \
int main() { \
    MQTTClient client; \
    int rc = MQTTClient_create(&client, "tcp://localhost:1883", "test_client", \
                               MQTTCLIENT_PERSISTENCE_NONE, NULL); \
    if (rc == MQTTCLIENT_SUCCESS) { \
        printf("MQTT library test: SUCCESS\n"); \
        MQTTClient_destroy(&client); \
        return 0; \
    } else { \
        printf("MQTT library test: FAILED (code %d)\n", rc); \
        return 1; \
    } \
} \
EOF
	@if gcc -o test_mqtt test_mqtt.c -lpaho-mqtt3c 2>/dev/null; then \
		echo "$(GREEN)[SUCCESS]$(NC) MQTT compilation test passed"; \
		rm -f test_mqtt test_mqtt.c; \
	else \
		echo "$(RED)[ERROR]$(NC) MQTT compilation test failed"; \
		rm -f test_mqtt.c; \
		exit 1; \
	fi

# Check for USB audio devices
check-audio-devices:
	@echo "$(BLUE)[INFO]$(NC) Checking for USB audio devices..."
	@if lsusb | grep -i audio > /dev/null; then \
		echo "$(GREEN)[SUCCESS]$(NC) USB audio devices found"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) No USB audio devices detected"; \
	fi
	@echo "$(BLUE)[INFO]$(NC) Available audio devices:"
	@aplay -l 2>/dev/null || echo "$(YELLOW)[WARNING]$(NC) Could not list audio devices"

# Check GPIO permissions
check-gpio:
	@echo "$(BLUE)[INFO]$(NC) Checking GPIO permissions..."
	@if [ -w /sys/class/gpio/export ]; then \
		echo "$(GREEN)[SUCCESS]$(NC) GPIO permissions OK"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) GPIO permissions may need adjustment"; \
	fi

# Install all dependencies
install-deps: check-os check-root update-packages install-system-deps install-audio-deps install-codec-deps install-networking-deps install-mqtt-broker install-mqtt-library test-mqtt check-audio-devices check-gpio
	@echo "$(GREEN)[SUCCESS]$(NC) All dependencies installed successfully!"

# Build the main application
build: api_call
	@echo "$(GREEN)[SUCCESS]$(NC) Build complete!"
	@chmod +x ./api_call
	@echo "$(BLUE)[INFO]$(NC) Executable created: api_call"

# Build main application
api_call: api_call.c
	@echo "$(BLUE)[INFO]$(NC) Building EchoStream application..."
	@$(CC) $(CFLAGS) -o api_call api_call.c $(LIBS)
	@echo "$(GREEN)[SUCCESS]$(NC) EchoStream application built"

# Clean build artifacts
clean:
	@echo "$(BLUE)[INFO]$(NC) Cleaning build artifacts..."
	@rm -f api_call test_mqtt test_mqtt.c
	@echo "$(GREEN)[SUCCESS]$(NC) Clean complete"

# Deep clean (including MQTT library)
deep-clean: clean
	@echo "$(BLUE)[INFO]$(NC) Deep cleaning (including MQTT library)..."
	@if [ -d "paho.mqtt.c" ]; then \
		cd paho.mqtt.c && make clean && cd ..; \
		echo "$(BLUE)[INFO]$(NC) MQTT library cleaned"; \
	fi
	@echo "$(GREEN)[SUCCESS]$(NC) Deep clean complete"

# Install to system
install: api_call
	@echo "$(BLUE)[INFO]$(NC) Installing to system..."
	@sudo cp api_call /usr/local/bin/
	@if [ -f "echostream.service" ]; then \
		sudo cp echostream.service /etc/systemd/system/; \
		sudo systemctl daemon-reload; \
		sudo systemctl enable echostream.service; \
		echo "$(GREEN)[SUCCESS]$(NC) Service installed and enabled"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) echostream.service not found, skipping service installation"; \
	fi
	@echo "$(GREEN)[SUCCESS]$(NC) Installation complete"
	@echo "$(BLUE)[INFO]$(NC) To start the service: sudo systemctl start echostream.service"

# Start the application
run: api_call
	@echo "$(BLUE)[INFO]$(NC) Starting EchoStream application..."
	@./api_call

# Show help
help:
	@echo "$(BLUE)EchoStream Makefile Help$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@echo "  all          - Install dependencies and build everything (default)"
	@echo "  install-deps - Install all system dependencies"
	@echo "  build        - Build the application (requires dependencies)"
	@echo "  clean        - Remove build artifacts"
	@echo "  deep-clean   - Clean everything including MQTT library"
	@echo "  install      - Install to system (/usr/local/bin)"
	@echo "  run          - Build and run the application"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "$(YELLOW)Quick start:$(NC)"
	@echo "  make all     # Install everything and build"
	@echo "  make run     # Build and run the application"

# Phony targets
.PHONY: all check-os check-root update-packages install-system-deps install-audio-deps install-codec-deps install-networking-deps install-mqtt-broker install-mqtt-library test-mqtt check-audio-devices check-gpio install-deps build clean deep-clean install run help