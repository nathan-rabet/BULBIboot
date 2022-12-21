#include "linux_boot.h"

#include "asm.h"
#include "console.h"
#include "crc32.h"
#include "kassert.h"
#include "kstring.h"
#include "number.h"
#include "stddef.h"
#include "uart.h"

static volatile void *KERNEL_ADDR = NULL;
static volatile void *DTB_ADDR = NULL;

void linux_boot()
{
    kassert(KERNEL_ADDR != NULL);
    kassert(DTB_ADDR != NULL);

    // Checing CRC32
    kputs("Checking kernel CRC32... ");
    u32 crc = crc32((void *)KERNEL_ADDR, KERNEL_BIN_LEN);
    kassertm(crc == KERNEL_CRC, "Kernel CRC32 mismatch");
    kputs("OK" CRLF);

    // Print current Exception Level (EL)
    u64 el;
    ASM("mrs %0, CurrentEL" : "=r"(el));
    el >>= 2;
    el &= 0x3;
    kputs("Current ARM Exception Level : EL");
    kputs(itoa64(el));
    kputs(CRLF);

    void _linux_boot(volatile void *dtb_addr, volatile void *kernel_addr);
    _linux_boot(DTB_ADDR, KERNEL_ADDR);
}

volatile const void *linux_get_dtb_addr(void)
{
    return DTB_ADDR;
}

volatile void *linux_get_kernel_addr(void)
{
    return KERNEL_ADDR;
}

void linux_set_kernel_addr(volatile void *kernel_addr)
{
    KERNEL_ADDR = kernel_addr;
}

void linux_set_dtb_addr(volatile void *dtb_addr)
{
    DTB_ADDR = dtb_addr;
}
