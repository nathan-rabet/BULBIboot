#include <stdint.h>

#include "asm.h"
#include "uart.h"

void bmain(void)
{
    uint64_t a = 0xA;
    uint64_t b = 0xB;
    (void)a;
    (void)b;

    char c = '\r';
    uint32_t console_char_counter = 0;
    while (1)
    {
        // In case of newline
        if (c == '\r' || c == '\n')
        {
            kputs("\r\n");
            kputs("pikaboot <3 ");
        }

        c = kgetc();

        // In case of deletion character
        if (c == 0x7F)
        {
            if (console_char_counter > 0)
            {
                kputs("\b \b");
                console_char_counter--;
            }
        }
        else
        {
            kputc(c);
            console_char_counter++;
        }
    }
}
