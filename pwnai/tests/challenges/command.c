/*
 * Command injection vulnerability example for testing PwnAI.
 * Compile with: gcc -o command command.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln() {
    char input[100];
    char command[150];
    
    printf("Enter a filename to check if it exists: ");
    fgets(input, sizeof(input), stdin);
    
    // Remove newline
    input[strcspn(input, "\n")] = 0;
    
    // Vulnerable command construction
    sprintf(command, "ls -la %s", input);
    
    printf("Executing command: %s\n", command);
    
    // Execute the command
    system(command);
}

int main() {
    printf("This program is vulnerable to command injection.\n");
    printf("Try to execute arbitrary commands!\n\n");
    
    // Disable buffering
    setbuf(stdout, NULL);
    
    vuln();
    
    printf("Program completed normally.\n");
    return 0;
} 