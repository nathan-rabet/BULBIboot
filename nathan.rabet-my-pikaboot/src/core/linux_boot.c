#include "linux_boot.h"

#include "kassert.h"
#include "stddef.h"

static void *KERNEL_ADDR = NULL;
static void *DTB_ADDR = NULL;

void linux_boot()
{
    kassert(KERNEL_ADDR != NULL);
    kassert(DTB_ADDR != NULL);

    void _linux_boot(void *dtb_addr, void *kernel_addr);
    _linux_boot(DTB_ADDR, KERNEL_ADDR);
}

const void *linux_get_dtb_addr(void)
{
    return DTB_ADDR;
}

void *linux_get_kernel_addr(void)
{
    return KERNEL_ADDR;
}

void linux_set_kernel_addr(void *kernel_addr)
{
    KERNEL_ADDR = kernel_addr;
}

void linux_set_dtb_addr(void *dtb_addr)
{
    DTB_ADDR = dtb_addr;
}
