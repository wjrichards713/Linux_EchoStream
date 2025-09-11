CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LIBS = -lcurl -ljson-c -lwebsockets -lportaudio -lopus -lssl -lcrypto -lpthread -lgpiod -lfftw3f

# Source files
SOURCES = main.c audio.c websocket.c gpio.c udp.c config.c crypto.c tone_detect.c
OBJECTS = $(SOURCES:.c=.o)

# Target executable
TARGET = echostream

# Check for required libraries
CHECK_LIBS = curl json-c websockets portaudio opus ssl crypto gpiod fftw3f

all: check-deps $(TARGET)

# Check for required dependencies
check-deps:
	@echo "Checking for required libraries..."
	@for lib in $(CHECK_LIBS); do \
		if ! pkg-config --exists $$lib 2>/dev/null && ! ldconfig -p | grep -q "lib$$lib"; then \
			echo "Warning: Library $$lib not found. Please install it."; \
		fi; \
	done
	@echo "Dependency check complete."

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET) with tone detection support..."
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Compile individual object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build files..."
	rm -f $(TARGET) $(OBJECTS)
	@echo "Clean complete."

# Install dependencies (for development)
install-deps:
	@echo "Installing required dependencies..."
	sudo apt update
	sudo apt install -y build-essential cmake git pkg-config wget curl make
	sudo apt install -y libportaudio2 libportaudiocpp0 portaudio19-dev alsa-utils
	sudo apt install -y libopus-dev libopus0
	sudo apt install -y libssl-dev openssl
	sudo apt install -y libjson-c-dev libjson-c5
	sudo apt install -y libcurl4-openssl-dev curl
	sudo apt install -y libwebsockets-dev
	sudo apt install -y libc6-dev
	sudo apt install -y raspi-gpio gpiod libgpiod-dev
	sudo apt install -y libfftw3-dev libfftw3-3
	@echo "Dependencies installed successfully!"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: clean $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo cp echostream.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable echostream.service
	@echo "Installation complete. Service will run at next boot."
	@echo "To start now: sudo systemctl start echostream.service"

# Legacy target for backward compatibility
api_call: $(TARGET)
	cp $(TARGET) api_call

.PHONY: all clean install api_call check-deps install-deps debug release
