#include "int.h"

///
/// @source: https://wiki.osdev.org/QEMU_AArch64_Virt_Bare_Bones
/// @source: https://krinkinmu.github.io/2020/11/29/PL011.html
///

volatile u8 *const uart = (u8 *)0x09000000;

static const u32 DR_OFFSET = 0x000;
static const u32 FR_OFFSET = 0x018;
// static const uint32_t IBRD_OFFSET = 0x024;
// static const uint32_t FBRD_OFFSET = 0x028;
// static const uint32_t LCR_OFFSET = 0x02c;
// static const uint32_t CR_OFFSET = 0x030;
// static const uint32_t IMSC_OFFSET = 0x038;
// static const uint32_t DMACR_OFFSET = 0x048;

int kputc(char c)
{
    while (*(uart + FR_OFFSET)
           & (1 << 5)) // wait until TXFF is 0 (FIFO is not full)
        ;
    *(uart + DR_OFFSET) = c;
    return 1;
}

char kgetc()
{
    while (*(uart + FR_OFFSET)
           & (1 << 4)) // wait until RXFE is 0 (FIFO is not empty)
        ;
    return *(uart + DR_OFFSET);
}

void kputs(const char *s)
{
    while (*s)
        kputc(*s++);
}
