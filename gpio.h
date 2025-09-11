#ifndef GPIO_H
#define GPIO_H

#include "echostream.h"

// GPIO state variables
extern int gpio_38_state;
extern int gpio_40_state;
extern int gpio_16_state;
extern int gpio_18_state;
extern pthread_mutex_t gpio_mutex;

// Function declarations
int init_gpio_pin(int pin);
int read_gpio_pin(int pin);
void cleanup_gpio(int pin);
void* gpio_monitor_worker(void* arg);

#endif // GPIO_H
