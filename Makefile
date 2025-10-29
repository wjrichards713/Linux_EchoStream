CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
LDFLAGS = -lportaudio -lopus -lcurl -lwebsockets -lfftw3 -lm -lpthread -lcrypto -lssl -ljson-c -lgpiod

# Check if libmosquitto is available and add if so
MOSQUITTO_CFLAGS := $(shell pkg-config --cflags libmosquitto 2>/dev/null || echo "")
MOSQUITTO_LDFLAGS := $(shell pkg-config --libs libmosquitto 2>/dev/null || echo "-lmosquitto")

# Try to detect if mosquitto header exists
ifneq ($(wildcard /usr/include/mosquitto.h),)
    CFLAGS += -DHAVE_MOSQUITTO
    LDFLAGS += -lmosquitto
endif
ifneq ($(wildcard /usr/local/include/mosquitto.h),)
    CFLAGS += -DHAVE_MOSQUITTO
    LDFLAGS += -lmosquitto
endif

# Source files
SOURCES = main.c audio.c websocket.c gpio.c udp.c config.c crypto.c tone_detect.c mqtt.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = echostream

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Install dependencies (for Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libportaudio2-dev libopus-dev libcurl4-openssl-dev libwebsockets-dev libfftw3-dev libmosquitto-dev

# Run the program
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

.PHONY: all clean install-deps run debug release