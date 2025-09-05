#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("=== GPIO Pin Mapping Test for Raspberry Pi 5 ===\n");
    
    // Test the mapping we're using
    int test_pins[] = {567, 568, 589, 590};
    int expected_lines[] = {0, 1, 20, 21};
    char* physical_pins[] = {"16", "18", "38", "40"};
    
    printf("GPIO Number -> gpiochip4 Line -> Physical Pin\n");
    printf("---------------------------------------------\n");
    
    for (int i = 0; i < 4; i++) {
        printf("GPIO %d -> Line %d -> Physical Pin %s\n", 
               test_pins[i], expected_lines[i], physical_pins[i]);
    }
    
    printf("\nTesting pinctrl commands:\n");
    printf("------------------------\n");
    
    for (int i = 0; i < 4; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "pinctrl set gpiochip4 %d ip pu", expected_lines[i]);
        printf("Command %d: %s\n", i+1, cmd);
    }
    
    printf("\nAlternative syntax (without chip name):\n");
    printf("-------------------------------------\n");
    
    for (int i = 0; i < 4; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "pinctrl set %d ip pu", expected_lines[i]);
        printf("Command %d: %s\n", i+1, cmd);
    }
    
    return 0;
}
