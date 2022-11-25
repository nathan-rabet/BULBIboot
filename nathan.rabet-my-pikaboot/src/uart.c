#include <stdint.h>

//
// https://wiki.osdev.org/QEMU_AArch64_Virt_Bare_Bones
//

volatile uint8_t *const uart = (uint8_t *)0x09000000;

void kputchar(char c)
{
    *uart = c;
}

void kputs(const char *s)
{
    while (*s)
        kputchar(*s++);
}
