CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g -DSAMPLE_RATE=48000
LDFLAGS = -lportaudio -lopus -lcurl -lwebsockets -lfftw3 -lm -lpthread -lcrypto -lssl -ljson-c -lgpiod

# Source files
SOURCES = main.c audio.c websocket.c gpio.c udp.c config.c crypto.c tone_detect.c
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
	sudo apt-get install -y libportaudio2-dev libopus-dev libcurl4-openssl-dev libwebsockets-dev libfftw3-dev

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