#ifndef UART_H
#define UART_H

#include <stdbool.h>
#include <stdint.h>

#include "virt.h"

///
/// @source: https://wiki.osdev.org/QEMU_AArch64_Virt_Bare_Bones
/// @source: https://krinkinmu.github.io/2020/11/29/PL011.html
/// @source: https://github.com/qemu/qemu/blob/master/hw/arm/virt.c
///

#define UART_REGISTER(UART, OFFSET) *(uart_t *)((char *)(UART) + (OFFSET))
typedef uint32_t uart_t;

// OFFSETS enum
enum uart_registers
{
    DR_OFFSET = 0x000,
    FR_OFFSET = 0x018,
    IBRD_OFFSET = 0x024,
    FBRD_OFFSET = 0x028,
    LCR_OFFSET = 0x02c,
    CR_OFFSET = 0x030,
    IMSC_OFFSET = 0x038,
    ICR_OFFSET = 0x44,
    DMACR_OFFSET = 0x048
};

enum cr_bits
{
    CR_UARTEN = 1 << 0,
    CR_TXEN = 1 << 8
};

enum lcr_bits
{
    LCR_STP2 = 1 << 3,
    LCR_FEN = 1 << 4
};

enum fr_bits
{
    FR_TXFF = 1 << 5,
    FR_BUSY = 1 << 3,
    FR_RXFE = 1 << 4,
    FR_TXFE = 1 << 7
};

#define BASE_CLOCK 24000000

// Frame format
#define DATA_FRAME_WIDTH 8
#define HAS_PARITY 0
#define STOP_BITS 1
#define BAUDRATE 115200

/**
 * @brief Setup an UART
 *
 * @param uart_addr The address of the UART (MMIO)
 */
void pl011_setup(volatile uart_t *uart_addr);

/**
 * @brief Check if the UART is enabled
 *
 * @param uart_addr The address of the UART (MMIO)
 * @return int 1 if enabled, 0 otherwise
 */
bool check_uart_enabled(volatile uart_t *uart_addr);

/**
 * @brief Write a character to the UART0
 *
 * @param c The character to write
 */
void kputc(char c);

/**
 * @brief Read a character from the UART0
 *
 * @return char The character read
 */
char kgetc();

/**
 * @brief Write a string to the UART0
 *
 * @param s The string to write
 */
void kputs(const char *s);

/**
 * @brief Read a character from the UART1
 *
 * @return char The character read
 */
char read_kermit();

#endif /* UART_H */
