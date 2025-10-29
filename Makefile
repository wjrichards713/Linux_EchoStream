CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
LDFLAGS = -lportaudio -lopus -lcurl -lwebsockets -lfftw3 -lm -lpthread -lcrypto -lssl -ljson-c -lgpiod

# Check if mosquitto header exists and enable MQTT support
MOSQUITTO_HEADER := $(shell test -f /usr/include/mosquitto.h && echo "yes" || test -f /usr/local/include/mosquitto.h && echo "yes" || echo "no")
ifeq ($(MOSQUITTO_HEADER),yes)
    CFLAGS += -DHAVE_MOSQUITTO
    LDFLAGS += -lmosquitto
    $(info MQTT support enabled (mosquitto.h found))
else
    $(info MQTT support disabled (mosquitto.h not found - install libmosquitto-dev to enable))
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