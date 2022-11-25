#include <stdint.h>

// SOURCES:
// https://wiki.osdev.org/QEMU_AArch64_Virt_Bare_Bones
// https://krinkinmu.github.io/2020/11/29/PL011.html
// https://android.googlesource.com/trusty/lk/common/+/dbfc27fcd8d5fd5c8031ab27201c6b2165c773b8/platform/qemu-virt/uart.c
//

volatile uint8_t *const uart = (uint8_t *)0x09000000;

static const uint32_t DR_OFFSET = 0x000;
static const uint32_t FR_OFFSET = 0x018;
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
