#include "linux_boot.h"

#include "kassert.h"
#include "stddef.h"

static volatile void *KERNEL_ADDR = NULL;
static volatile void *DTB_ADDR = NULL;

void linux_boot()
{
    kassert(KERNEL_ADDR != NULL);
    kassert(DTB_ADDR != NULL);

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
