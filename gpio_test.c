#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

static int running = 1;

void signal_handler(int sig) {
    running = 0;
}

int init_gpio_pin(int pin) {
    char path[64], value[8];
    int fd;
    
    // First try to unexport the pin in case it's already exported
    snprintf(path, sizeof(path), "/sys/class/gpio/unexport");
    if ((fd = open(path, O_WRONLY)) != -1) {
        snprintf(value, sizeof(value), "%d", pin);
        write(fd, value, strlen(value));  // Ignore errors
        close(fd);
    }
    
    usleep(100000);
    
    snprintf(path, sizeof(path), "/sys/class/gpio/export");
    if ((fd = open(path, O_WRONLY)) == -1) {
        printf("ERROR: Cannot open GPIO export file %s: %s\n", path, strerror(errno));
        return 0;
    }
    snprintf(value, sizeof(value), "%d", pin);
    if (write(fd, value, strlen(value)) == -1) {
        printf("ERROR: Cannot export GPIO pin %d: %s\n", pin, strerror(errno));
        close(fd);
        return 0;
    }
    close(fd);
    
    usleep(100000);
    
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", pin);
    if ((fd = open(path, O_WRONLY)) == -1) {
        printf("ERROR: Cannot open GPIO direction file %s: %s\n", path, strerror(errno));
        return 0;
    }
    if (write(fd, "in", 2) == -1) {
        printf("ERROR: Cannot set GPIO pin %d direction: %s\n", pin, strerror(errno));
        close(fd);
        return 0;
    }
    close(fd);
    
    // Try to enable pull-up resistor using pinctrl command for Pi 5
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "pinctrl set %d ip pu", pin - 569);
    printf("Setting pull-up for GPIO %d: %s\n", pin - 569, cmd);
    system(cmd);
    
    printf("GPIO pin %d initialized successfully\n", pin);
    return 1;
}

int read_gpio_pin(int pin) {
    char path[64], value[4];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", pin);
    if ((fd = open(path, O_RDONLY)) == -1) {
        printf("ERROR: Cannot open GPIO value file %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    if (read(fd, value, 3) == -1) {
        printf("ERROR: Cannot read GPIO pin %d value: %s\n", pin, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    
    return (value[0] == '0') ? 0 : 1;
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

int main() {
    int gpio_pin_38 = 589;  // GPIO 20 (physical pin 38) on RPi5
    int gpio_pin_40 = 590;  // GPIO 21 (physical pin 40) on RPi5
    
    int prev_val_38 = -1, prev_val_40 = -1;
    int curr_val_38, curr_val_40;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("GPIO Test Script\n");
    printf("Physical Pin 38 (GPIO 20) -> GPIO %d\n", gpio_pin_38);
    printf("Physical Pin 40 (GPIO 21) -> GPIO %d\n", gpio_pin_40);
    printf("Press Ctrl+C to exit\n\n");
    
    if (!init_gpio_pin(gpio_pin_38)) {
        printf("Failed to initialize GPIO pin 38\n");
        return 1;
    }
    
    if (!init_gpio_pin(gpio_pin_40)) {
        printf("Failed to initialize GPIO pin 40\n");
        cleanup_gpio(gpio_pin_38);
        return 1;
    }
    
    printf("GPIO pins initialized. Monitoring for changes...\n");
    printf("Connect pins to GND to see LOW (0), disconnect for HIGH (1)\n\n");
    
    while (running) {
        curr_val_38 = read_gpio_pin(gpio_pin_38);
        curr_val_40 = read_gpio_pin(gpio_pin_40);
        
        if (curr_val_38 != prev_val_38 && curr_val_38 != -1) {
            printf("PIN 38 (GPIO 20): %s (%d)\n", 
                   curr_val_38 == 0 ? "CONNECTED to GND" : "DISCONNECTED from GND", 
                   curr_val_38);
            prev_val_38 = curr_val_38;
        }
        
        if (curr_val_40 != prev_val_40 && curr_val_40 != -1) {
            printf("PIN 40 (GPIO 21): %s (%d)\n", 
                   curr_val_40 == 0 ? "CONNECTED to GND" : "DISCONNECTED from GND", 
                   curr_val_40);
            prev_val_40 = curr_val_40;
        }
        
        usleep(100000);  // Check every 100ms
    }
    
    printf("\nCleaning up...\n");
    cleanup_gpio(gpio_pin_38);
    cleanup_gpio(gpio_pin_40);
    
    return 0;
}