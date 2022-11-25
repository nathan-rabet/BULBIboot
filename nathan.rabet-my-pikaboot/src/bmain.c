#include <stdint.h>
#include <string.h>

#include "asm.h"
#include "uart.h"

#define BUF_SIZE 1024

void bmain(void)
{
    char buf[BUF_SIZE] = { 0 };

    uint32_t console_char_i = 0;

    kputs("\r\n");
    kputs("pikaboot <3 ");
    while (1)
    {
        char c = kgetc();

        // In case of newline
        if (c == '\r' || c == '\n')
        {
            console_char_i = 0;

            kputs("\r\n");
            kputs("pikaboot <3 ");
        }

        // In case of deletion character
        else if (c == 0x7F)
        {
            if (console_char_i > 0)
            {
                kputs("\b \b");
                console_char_i--;
            }
        }

        // In case of normal character
        else if (console_char_i < BUF_SIZE)
        {
            buf[console_char_i++] = c;
            kputc(c);
        }

        (void)buf;
    }
}
