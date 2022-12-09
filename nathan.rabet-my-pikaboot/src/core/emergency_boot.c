#include "emergency_boot.h"

#include "asm.h"
#include "int.h"
#include "kstring.h"
#include "number.h"
#include "uart.h"

static void uart_write(char c, volatile uart_t *uart_addr)
{
    while (*(uart_addr + FR_OFFSET)
           & (1 << 5)) // wait until TXFF is 0 (FIFO is not full)
        ;
    *(uart_addr + DR_OFFSET) = c;
}

void emergency_boot(void)
{}
