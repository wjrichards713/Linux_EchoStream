CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lcurl -ljson-c -lwebsockets -lportaudio -lopus -lssl -lcrypto -lpthread -lgpiod

# Source files
SOURCES = main.c audio.c websocket.c gpio.c udp.c config.c crypto.c
OBJECTS = $(SOURCES:.c=.o)

# Target executable
TARGET = echostream

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Compile individual object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@if [ -f "echostream.service" ]; then \
		sudo cp echostream.service /etc/systemd/system/; \
		sudo systemctl daemon-reload; \
		sudo systemctl enable echostream.service; \
		echo "Service installed and enabled."; \
	else \
		echo "Warning: echostream.service not found, skipping service installation."; \
	fi
	@echo "Installation complete. Binary installed to /usr/local/bin/$(TARGET)"
	@echo "To start service: sudo systemctl start echostream.service"

# Install without service (binary only)
install-bin: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "Binary installed to /usr/local/bin/$(TARGET)"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo systemctl stop echostream.service 2>/dev/null || true
	sudo systemctl disable echostream.service 2>/dev/null || true
	sudo rm -f /etc/systemd/system/echostream.service
	sudo systemctl daemon-reload
	@echo "Uninstallation complete."

# Legacy target for backward compatibility
api_call: $(TARGET)
	cp $(TARGET) api_call

.PHONY: all clean install install-bin uninstall api_call
