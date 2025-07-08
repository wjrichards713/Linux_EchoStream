sudo apt update
sudo apt upgrade -y
sudo apt install libcurl4-openssl-dev libjson-c-dev libwebsockets-dev libportaudio2 libopus-dev libssl-dev
sudo apt install libportaudio2 libportaudiocpp0 portaudio19-dev
gcc -Wall -Wextra -o api_call api_call.c $(pkg-config --cflags --libs libcurl json-c libwebsockets portaudio-2.0 opus openssl)
chmod +x ./api_call
./api_call
