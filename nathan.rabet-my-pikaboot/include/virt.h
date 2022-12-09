#ifndef VIRT_H
#define VIRT_H

enum arm_virt_mmio
{
    FLASH_START = 0x000100000,
    UART0_ADDR = 0x09000000,
    VIRT_SECURE_UART = 0x09040000,
    RAM_START = 0x40000000,
    TEXT_START = 0x40080000,
};

#endif /* VIRT_H */
