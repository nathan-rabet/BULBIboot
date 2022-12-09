#include "uart.h"

#include <stdint.h>

#include "virt.h"

// ------------------------------------------------------------
// UART PL011
// ------------------------------------------------------------

#define BAUDRATE_DIV (4 * BASE_CLOCK / (16 * BAUDRATE))
#define IBRD (BAUDRATE_DIV & 0x3F)
#define FBRD ((BAUDRATE_DIV >> 6) & 0xFFFF)

inline static void wait_transmission_complete(volatile uart_t *uart_addr)
{
    while ((UART_REGISTER(uart_addr, FR_OFFSET)) & FR_BUSY)
        ;
}

void pl011_setup(volatile uart_t *uart_addr)
{
    // Disable UART
    UART_REGISTER(uart_addr, CR_OFFSET) &= ~CR_UARTEN;

    // Wait for any ongoing transmissions to complete
    wait_transmission_complete(uart_addr);

    // Flush FIFOs
    UART_REGISTER(uart_addr, LCR_OFFSET) &= ~LCR_FEN;

    // Set frequency divisors (UARTIBRD and UARTFBRD) to configure the speed
    // of the UART
    UART_REGISTER(uart_addr, IBRD_OFFSET) = IBRD;
    UART_REGISTER(uart_addr, FBRD_OFFSET) = FBRD;

    // Mask all interrupts by setting corresponding bits to 1
    UART_REGISTER(uart_addr, IMSC_OFFSET) = 0x7FF;

    // Disable DMA by setting all bits to 0
    UART_REGISTER(uart_addr, DMACR_OFFSET) = 0;

    // I only need transmission, so that's the only thing I enabled.
    UART_REGISTER(uart_addr, CR_OFFSET) = CR_TXEN;

    // Enable UART
    UART_REGISTER(uart_addr, CR_OFFSET) |= CR_UARTEN;
}

bool check_uart_enabled(volatile uart_t *uart_addr)
{
    if ((UART_REGISTER(uart_addr, CR_OFFSET) & CR_UARTEN) == 0)
        return false;
    return true;
}

static void uart_write(char c, volatile uart_t *uart_addr)
{
    wait_transmission_complete(uart_addr);
    while (UART_REGISTER(uart_addr, FR_OFFSET)
           & FR_TXFF) // wait until TXFF is 0 (FIFO is not full)
        ;
    UART_REGISTER(uart_addr, DR_OFFSET) = c;
}

static char uart_read(volatile uart_t *uart_addr)
{
    wait_transmission_complete(uart_addr);
    while (UART_REGISTER(uart_addr, FR_OFFSET)
           & FR_RXFE) // wait until RXFE is 0 (FIFO is not empty)
        ;
    return UART_REGISTER(uart_addr, DR_OFFSET);
}

// ------------------------------------------------------------
// UART0 is for user input/output
// ------------------------------------------------------------

void kputc(char c)
{
    uart_write(c, (uart_t *)UART0_ADDR);
}

char kgetc()
{
    return uart_read((uart_t *)UART0_ADDR);
}

void kputs(const char *s)
{
    while (*s)
        kputc(*s++);
}

// ------------------------------------------------------------
// UART1 is for emergency boot download (kermit)
// ------------------------------------------------------------

char read_kermit()
{
    // Go to

    return uart_read((uart_t *)VIRT_SECURE_UART);
}
