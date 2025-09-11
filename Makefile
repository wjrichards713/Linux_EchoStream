CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lcurl -ljson-c -lwebsockets -lportaudio -lopus -lssl -lcrypto -lpthread -lgpiod -lfftw3f

# Source files
SOURCES = main.c audio.c websocket.c gpio.c udp.c config.c crypto.c tone_detect.c
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
	sudo cp echostream.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable echostream.service
	@echo "Installation complete. Service will run at next boot."
	@echo "To start now: sudo systemctl start echostream.service"

# Legacy target for backward compatibility
api_call: $(TARGET)
	cp $(TARGET) api_call

.PHONY: all clean install api_call
