#include "linux_boot.h"

#include "asm.h"
#include "console.h"
#include "crc32.h"
#include "crypto.h"
#include "kassert.h"
#include "kstring.h"
#include "number.h"
#include "stddef.h"
#include "uart.h"

static const unsigned char kernel_sig[] = {
#include "thirdparty/arm64/Image.sig.hex"
};

static const unsigned char kernel_pub_der_key[] = {
#include "thirdparty/arm64/Image.pub.der.hex"
};

static volatile void *KERNEL_ADDR = NULL;
static volatile void *DTB_ADDR = NULL;

static bool verify_kernel_signature(void)
{
    rsa_key key = { 0 };
    bool is_parsed =
        parse_rsa_der(kernel_pub_der_key, sizeof(kernel_pub_der_key), &key);
    kassertm(is_parsed, "Failed to parse RSA public key");

    bool is_verified = rsa_verify_sig((void *)KERNEL_ADDR, KERNEL_IMG_LEN,
                                      kernel_sig, sizeof(kernel_sig), &key);
    return is_verified;
}

void linux_boot()
{
    kassert(KERNEL_ADDR != NULL);
    kassert(DTB_ADDR != NULL);

    // Checing CRC32
    kputs("Checking kernel CRC32... ");
    u32 crc = crc32((void *)KERNEL_ADDR, KERNEL_IMG_LEN);
    if (crc != KERNEL_CRC)
    {
        kputs(RED_STR("FAILED") CRLF);
        kputs("Kernel CRC32 mismatch: expected ");
        kputs(itoa64hex(KERNEL_CRC));
        kputs(", got ");
        kputs(itoa64hex(crc));
        kputs(CRLF);
        kputs("Aborting..." CRLF);
        return;
    }
    else
        kputs(GREEN_STR("OK") CRLF);

    // Checking signature
    kputs("Checking kernel signature... ");
    if (!verify_kernel_signature())
    {
        kputs(RED_STR("FAILED") CRLF);
        kputs("Kernel signature verification failed" CRLF);
        kputs("Aborting..." CRLF);
        return;
    }
    else
        kputs(GREEN_STR("OK") CRLF);

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
