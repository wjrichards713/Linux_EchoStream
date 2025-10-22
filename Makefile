CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lportaudio -lopus -lcurl -lwebsockets -lm -lpthread -lcrypto -lssl -ljson-c -lgpiod

# Source files
SOURCES = main.c audio.c websocket.c gpio.c udp.c config.c crypto.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = echostream

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Build the test executable

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_TARGET)

# Install dependencies (for Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libportaudio2-dev libopus-dev libcurl4-openssl-dev libwebsockets-dev libcjson-dev

# Run the program
run: $(TARGET)
	./$(TARGET)

# Run the test program
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Debug build
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

.PHONY: all clean install-deps run debug release