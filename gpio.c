#include "gpio.h"
#include "audio.h"
#include "websocket.h"
#include <unistd.h>

// GPIO state variables
int gpio_38_state = 0;
int gpio_40_state = 0;
int gpio_16_state = 0;  // GPIO pin 16 (physical pin 16) for channel 3
int gpio_18_state = 0;  // GPIO pin 18 (physical pin 18) for channel 4
pthread_mutex_t gpio_mutex = PTHREAD_MUTEX_INITIALIZER;

int init_gpio_pin(int pin) {
    char cmd[64];

    // Set pin as input with pull-up resistor
    snprintf(cmd, sizeof(cmd), "pinctrl set %d ip pu", pin);
    if (system(cmd) != 0) {
        printf("ERROR: Cannot configure GPIO pin %d via pinctrl\n", pin);
        return 0;
    }

    printf("GPIO pin %d initialized successfully (input + pull-up)\n", pin);
    return 1;
}

int read_gpio_pin(int pin) {
    struct gpiod_chip *chip;
    struct gpiod_line *line;
    int val;

    chip = gpiod_chip_open_by_name("gpiochip0");
    if (!chip) return -1;

    line = gpiod_chip_get_line(chip, pin);
    if (!line) {
        gpiod_chip_close(chip);
        return -1;
    }

    if (gpiod_line_request_input(line, "gpio_monitor") < 0) {
        gpiod_chip_close(chip);
        return -1;
    }

    val = gpiod_line_get_value(line);

    gpiod_line_release(line);
    gpiod_chip_close(chip);

    return val;  // 0 = low, 1 = high
}

void cleanup_gpio(int pin) {
    char path[64], value[8];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/unexport");
    if ((fd = open(path, O_WRONLY)) != -1) {
        snprintf(value, sizeof(value), "%d", pin);
        write(fd, value, strlen(value));
        close(fd);
    }
}

void* gpio_monitor_worker(void* arg) {
    int gpio_pin_38 = 20;   // GPIO 20 (physical pin 38)
    int gpio_pin_40 = 21;   // GPIO 21 (physical pin 40)
    int gpio_pin_16 = 23;   // GPIO 23 (physical pin 16)
    int gpio_pin_18 = 24;   // GPIO 24 (physical pin 18)

    printf("GPIO monitor worker started\n");

    // Initialize all pins via pinctrl
    if (!init_gpio_pin(gpio_pin_38) ||
        !init_gpio_pin(gpio_pin_40) ||
        !init_gpio_pin(gpio_pin_16) ||
        !init_gpio_pin(gpio_pin_18)) {
        printf("Failed to initialize one or more GPIO pins\n");
        return NULL;
    }

    printf("GPIO pins initialized. Reading initial states...\n");

    // Read initial states
    pthread_mutex_lock(&gpio_mutex);
    gpio_38_state = read_gpio_pin(gpio_pin_38);
    gpio_40_state = read_gpio_pin(gpio_pin_40);
    gpio_16_state = read_gpio_pin(gpio_pin_16);
    gpio_18_state = read_gpio_pin(gpio_pin_18);
    pthread_mutex_unlock(&gpio_mutex);

    // Print initial states and set gpio_active for any pins that are already active
    printf("PIN 38 initial state: %s\n", (gpio_38_state == 0) ? "ACTIVE" : "INACTIVE");
    printf("PIN 40 initial state: %s\n", (gpio_40_state == 0) ? "ACTIVE" : "INACTIVE");
    printf("PIN 16 initial state: %s\n", (gpio_16_state == 0) ? "ACTIVE" : "INACTIVE");
    printf("PIN 18 initial state: %s\n", (gpio_18_state == 0) ? "ACTIVE" : "INACTIVE");
    
    // Set gpio_active for any pins that are already active at startup
    if (gpio_38_state == 0) {
        for (int i = 0; i < 4; i++) {
            if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[0]) == 0) {
                channels[i].audio.gpio_active = 1;
                printf("Channel %s audio ENABLED (PIN 38 was already active)\n", global_channel_ids[0]);
                break;
            }
        }
    }
    
    if (gpio_40_state == 0) {
        for (int i = 0; i < 4; i++) {
            if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[1]) == 0) {
                channels[i].audio.gpio_active = 1;
                printf("Channel %s audio ENABLED (PIN 40 was already active)\n", global_channel_ids[1]);
                break;
            }
        }
    }
    
    if (gpio_16_state == 0) {
        for (int i = 0; i < 4; i++) {
            if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[2]) == 0) {
                channels[i].audio.gpio_active = 1;
                printf("Channel %s audio ENABLED (PIN 16 was already active)\n", global_channel_ids[2]);
                break;
            }
        }
    }
    
    if (gpio_18_state == 0) {
        for (int i = 0; i < 4; i++) {
            if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[3]) == 0) {
                channels[i].audio.gpio_active = 1;
                printf("Channel %s audio ENABLED (PIN 18 was already active)\n", global_channel_ids[3]);
                break;
            }
        }
    }

    printf("Monitoring GPIO pins for changes...\n");
    printf("GPIO Status will be displayed every 10 seconds\n");

    int status_counter = 0;
    while (!global_interrupted) {
        int curr_val_38 = read_gpio_pin(gpio_pin_38);
        int curr_val_40 = read_gpio_pin(gpio_pin_40);
        int curr_val_16 = read_gpio_pin(gpio_pin_16);
        int curr_val_18 = read_gpio_pin(gpio_pin_18);

        pthread_mutex_lock(&gpio_mutex);

        // Check for changes and send WebSocket events
        if (curr_val_38 != gpio_38_state && curr_val_38 != -1) {
            gpio_38_state = curr_val_38;
            printf("PIN 38: %s\n", curr_val_38 == 0 ? "ACTIVE" : "INACTIVE");
            
            // Find and set gpio_active flag for the correct audio stream
            for (int i = 0; i < 4; i++) {
                if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[0]) == 0) {
                    channels[i].audio.gpio_active = (curr_val_38 == 0) ? 1 : 0;
                    printf("Channel %s audio %s\n", global_channel_ids[0], 
                           channels[i].audio.gpio_active ? "ENABLED" : "DISABLED");
                    break;
                }
            }
            
            send_websocket_transmit_event(global_channel_ids[0], curr_val_38 == 0 ? 1 : 0);
        }

        if (curr_val_40 != gpio_40_state && curr_val_40 != -1) {
            gpio_40_state = curr_val_40;
            printf("PIN 40: %s\n", curr_val_40 == 0 ? "ACTIVE" : "INACTIVE");
            
            // Find and set gpio_active flag for the correct audio stream
            for (int i = 0; i < 4; i++) {
                if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[1]) == 0) {
                    channels[i].audio.gpio_active = (curr_val_40 == 0) ? 1 : 0;
                    printf("Channel %s audio %s\n", global_channel_ids[1], 
                           channels[i].audio.gpio_active ? "ENABLED" : "DISABLED");
                    break;
                }
            }
            
            send_websocket_transmit_event(global_channel_ids[1], curr_val_40 == 0 ? 1 : 0);
        }

        if (curr_val_16 != gpio_16_state && curr_val_16 != -1) {
            gpio_16_state = curr_val_16;
            printf("PIN 16: %s\n", curr_val_16 == 0 ? "ACTIVE" : "INACTIVE");
            
            // Find and set gpio_active flag for the correct audio stream
            for (int i = 0; i < 4; i++) {
                if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[2]) == 0) {
                    channels[i].audio.gpio_active = (curr_val_16 == 0) ? 1 : 0;
                    printf("Channel %s audio %s\n", global_channel_ids[2], 
                           channels[i].audio.gpio_active ? "ENABLED" : "DISABLED");
                    break;
                }
            }
            
            send_websocket_transmit_event(global_channel_ids[2], curr_val_16 == 0 ? 1 : 0);
        }

        if (curr_val_18 != gpio_18_state && curr_val_18 != -1) {
            gpio_18_state = curr_val_18;
            printf("PIN 18: %s\n", curr_val_18 == 0 ? "ACTIVE" : "INACTIVE");
            
            // Find and set gpio_active flag for the correct audio stream
            for (int i = 0; i < 4; i++) {
                if (channels[i].active && strcmp(channels[i].audio.channel_id, global_channel_ids[3]) == 0) {
                    channels[i].audio.gpio_active = (curr_val_18 == 0) ? 1 : 0;
                    printf("Channel %s audio %s\n", global_channel_ids[3], 
                           channels[i].audio.gpio_active ? "ENABLED" : "DISABLED");
                    break;
                }
            }
            
            send_websocket_transmit_event(global_channel_ids[3], curr_val_18 == 0 ? 1 : 0);
        }

        // Display status every 10 seconds (100 iterations * 100ms = 10 seconds)
        status_counter++;
        if (status_counter >= 30) {
            printf("\n=== GPIO Status Report (every 10 seconds) ===\n");
            printf("PIN 38 (GPIO 20): %s (Channel: %s)\n", 
                   curr_val_38 == 0 ? "ACTIVE" : "INACTIVE", global_channel_ids[0]);
            printf("PIN 40 (GPIO 21): %s (Channel: %s)\n", 
                   curr_val_40 == 0 ? "ACTIVE" : "INACTIVE", global_channel_ids[1]);
            printf("PIN 16 (GPIO 23): %s (Channel: %s)\n", 
                   curr_val_16 == 0 ? "ACTIVE" : "INACTIVE", global_channel_ids[2]);
            printf("PIN 18 (GPIO 24): %s (Channel: %s)\n", 
                   curr_val_18 == 0 ? "ACTIVE" : "INACTIVE", global_channel_ids[3]);
            printf("==========================================\n\n");
            status_counter = 0;
        }

        pthread_mutex_unlock(&gpio_mutex);
        usleep(100000); // 100 ms poll
    }

    printf("GPIO monitor worker stopped\n");
    return NULL;
}
