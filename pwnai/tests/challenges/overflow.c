/*
 * Simple buffer overflow vulnerable program for testing PwnAI.
 * Compile with: gcc -fno-stack-protector -no-pie -o overflow overflow.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("Congratulations! You have successfully exploited the buffer overflow.\n");
    printf("flag{simple_buffer_overflow_solved}\n");
    exit(0);
}

void vuln() {
    char buffer[64];
    
    printf("Enter some text: ");
    gets(buffer);
    
    printf("You entered: %s\n", buffer);
}

int main() {
    printf("This program is vulnerable to a buffer overflow.\n");
    printf("Try to call the win() function!\n\n");
    
    // Disable buffering
    setbuf(stdout, NULL);
    
    vuln();
    
    printf("Program completed normally.\n");
    return 0;
} 