/*
 * Format string vulnerability example for testing PwnAI.
 * Compile with: gcc -o format format.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int secret_value = 0x12345678;

void print_flag() {
    printf("Congratulations! You have successfully exploited the format string vulnerability.\n");
    printf("flag{format_string_vulnerability_solved}\n");
    exit(0);
}

void vuln() {
    char buffer[100];
    
    printf("Enter some text: ");
    fgets(buffer, sizeof(buffer), stdin);
    
    // Vulnerable format string
    printf(buffer);
    
    // Check if the secret value has been modified
    if (secret_value == 0x41414141) {
        print_flag();
    } else {
        printf("\nSecret value: 0x%08x\n", secret_value);
    }
}

int main() {
    printf("This program is vulnerable to a format string attack.\n");
    printf("Try to change the secret_value to 0x41414141!\n\n");
    
    // Disable buffering
    setbuf(stdout, NULL);
    
    vuln();
    
    printf("Program completed normally.\n");
    return 0;
} 