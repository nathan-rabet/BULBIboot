#include "crypto.h"
#include "kalloc.h"
#include "kstring.h"
#include "pflash.h"
#include "uart.h"

static void init_crypto(void)
{
    ltc_mp = ltm_desc;
    register_all_ciphers();
    register_all_hashes();
}

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, void *x4)
{
    (void)x0;
    (void)x1;
    (void)x2;
    (void)x3;
    (void)x4;

    // Initialize malloc heap
    kalloc_init();

    // Initialize crypto
    init_crypto();

    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    // Verify encrypted bootloader signature
    kputs("Bootloader signature verification: ");
    verify_pflash(x4);
    kputs("OK" CRLF);

    // Decrypt bootloader
    kputs("Bootloader decryption: ");
    decrypt_pflash(x4);
    kputs("OK" CRLF);

    // Jump to decrypted bootloader
    kputs("Jumping to bootloader" CRLF);
    void (*bootloader)(u64, u64, u64, u64, void *) =
        (void (*)(u64, u64, u64, u64, void *))x4 + BOOTLOADER_BIN_ADDR;
    bootloader(x0, x1, x2, x3, x4);
}
