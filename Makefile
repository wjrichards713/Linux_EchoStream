CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lcurl -ljson-c -lwebsockets -lportaudio -lopus -lssl -lcrypto -lpthread

all: api_call

api_call: api_call.c
	$(CC) $(CFLAGS) -o api_call api_call.c $(LIBS)

clean:
	rm -f api_call

install: api_call
	sudo cp api_call /usr/local/bin/
	sudo cp api_call.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable api_call.service
	@echo "Installation complete. Service will run at next boot."
	@echo "To start now: sudo systemctl start api_call.service"