#include <stdint.h>

#include "asm.h"
#include "uart.h"

void bmain(void)
{
    uint64_t a = 0xA;
    uint64_t b = 0xB;
    (void)a;
    (void)b;

    kputs("Hello, world!");

    while (1)
        ;
}
