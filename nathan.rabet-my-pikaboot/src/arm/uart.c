#include "uart.h"

#include <stdint.h>

#include "board.h"
#include "kassert.h"
#include "kstring.h"

// ------------------------------------------------------------
//
// ██    ██  █████  ██████  ████████     ██████  ██       ██████   ██  ██
// ██    ██ ██   ██ ██   ██    ██        ██   ██ ██      ██  ████ ███ ███
// ██    ██ ███████ ██████     ██        ██████  ██      ██ ██ ██  ██  ██
// ██    ██ ██   ██ ██   ██    ██        ██      ██      ████  ██  ██  ██
//  ██████  ██   ██ ██   ██    ██        ██      ███████  ██████   ██  ██
//
// ------------------------------------------------------------

// I/O
inline static void wait_transmission_complete(volatile uart_t *uart_addr)
{
    (void)uart_addr;
    while (check_transmission_busy(uart_addr))
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
#define BAUDRATE_DIV (4 * BASE_CLOCK / (16 * BAUDRATE))
#define IBRD (BAUDRATE_DIV & 0x3F)
#define FBRD ((BAUDRATE_DIV >> 6) & 0xFFFF)

    UART_REGISTER(uart_addr, IBRD_OFFSET) = IBRD;
    UART_REGISTER(uart_addr, FBRD_OFFSET) = FBRD;

    // Enable all interrupts by setting corresponding bits to 1
    uart_enable_interrupts(uart_addr);

    // Set Line Control Register
    UART_REGISTER(uart_addr, LCR_OFFSET) = ((DATA_FRAME_WIDTH - 1) & 0x3)
        | (HAS_PARITY << 1) | (HAS_STOP_BITS << 2) | (HAS_TWO_STOP_BITS << 3)
        | (LCR_FEN);

    // Disable DMA by setting all bits to 0
    UART_REGISTER(uart_addr, DMACR_OFFSET) = 0;

    // I only need transmission, so that's the only thing I enabled.
    UART_REGISTER(uart_addr, CR_OFFSET) = CR_TXEN;

    // Enable UART
    UART_REGISTER(uart_addr, CR_OFFSET) |= CR_UARTEN;
}

#define LOOP_BREAKER 100
u64 uart_write(const unsigned char *buf, u64 size, volatile uart_t *uart_addr)
{
    // Chek if UART is enabled
    if (!check_uart_enabled(uart_addr))
        return -1;

    for (u64 i = 0; i < size; i++)
    {
        wait_transmission_complete(uart_addr);

        u64 breaker = LOOP_BREAKER;
        for (; breaker > 0; breaker--)
            if (check_uart_write_ready(uart_addr))
            {
                UART_REGISTER(uart_addr, DR_OFFSET) = buf[i];
                break;
            }

        if (breaker == 0)
            return i;
    }

    return size;
}

u64 uart_read(unsigned char *buf, u64 size, volatile uart_t *uart_addr)
{
    // Chek if UART is enabled
    if (!check_uart_enabled(uart_addr))
        return -1;

    for (u64 i = 0; i < size; i++)
    {
        u64 breaker = LOOP_BREAKER;
        for (; breaker > 0; breaker--)
            if (check_uart_read_ready(uart_addr))
            {
                buf[i] = UART_REGISTER(uart_addr, DR_OFFSET);
                break;
            }

        if (breaker == 0)
            return i;
    }

    return size;
}

// Checks
bool check_uart_enabled(volatile uart_t *uart_addr)
{
    if ((UART_REGISTER(uart_addr, CR_OFFSET) & CR_UARTEN) == 0) // UART disabled
        return false;
    return true;
}

bool check_uart_interrupts_enabled(volatile uart_t *uart_addr)
{
    if ((UART_REGISTER(uart_addr, IMSC_OFFSET) & 0x7FF)
        == 0) // All interrupts disabled
        return false;
    return true;
}

bool check_transmission_busy(volatile uart_t *uart_addr)
{
    if (UART_REGISTER(uart_addr, FR_OFFSET) & FR_BUSY) // Transmission busy
        return true;
    return false;
}

bool check_uart_read_ready(volatile uart_t *uart_addr)
{
    if (UART_REGISTER(uart_addr, FR_OFFSET) & FR_RXFE) // RX FIFO empty
        return false;
    return true;
}

bool check_uart_write_ready(volatile uart_t *uart_addr)
{
    if (UART_REGISTER(uart_addr, FR_OFFSET) & FR_TXFF) // TX FIFO full
        return false;
    return true;
}

void uart_disable_interrupts(volatile uart_t *uart_addr)
{
    UART_REGISTER(uart_addr, IMSC_OFFSET) = 0;
}

void uart_enable_interrupts(volatile uart_t *uart_addr)
{
    UART_REGISTER(uart_addr, IMSC_OFFSET) = 0x7FF;
}

// ------------------------------------------------------------
// UART0 is for user input/output
// ------------------------------------------------------------

void kputc(char c)
{
    if (uart_write((unsigned char *)&c, 1, (uart_t *)UART0_BOARD_ADDR)
        == (u64)-1)
        return; // panic("UART0 is not working");
}

char kgetc()
{
    while (!check_uart_read_ready((volatile uart_t *)UART0_BOARD_ADDR))
        ;

    char c = 0;
    if (uart_read((unsigned char *)&c, 1, (uart_t *)UART0_BOARD_ADDR)
        == (u64)-1)
        return c; // panic("UART0 is not working");

    return c;
}

void kputs(const char *s)
{
    if (uart_write((unsigned char *)s, strlen(s), (uart_t *)UART0_BOARD_ADDR)
        == (u64)-1)
        return; // panic("UART0 is not working");
}
