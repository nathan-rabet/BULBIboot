#include "console.h"
#include "crypto.h"
#include "kalloc.h"
#include "kstring.h"
#include "number.h"
#include "pflash.h"
#include "uart.h"

const char *preboot_header = RED_STR(
    " ______  _     _ _       ______ _____                     _               "
    "                                          ")
    CRLF RED_STR(
        "(____  \\| |   | | |     (____  (_____)                   | |     "
        "           _                       _               ")
        CRLF RED_STR(" ____)  ) |   | | |      ____)  ) _      ____   ____ "
                     "____| | _   ___  "
                     " ___ | |_      ___ _   _  ___| |_  ____ ____  ")
            CRLF RED_STR(
                "|  __  (| |   | | |     |  __  ( | |    |  _ \\ / ___) _ "
                " ) || \\ / _ \\ / _ \\|  _)    /___) | | |/___)  _)/ _  "
                ")    \\ ")
                CRLF RED_STR(
                    "| |__)  ) |___| | |_____| |__)  )| |_   | | | | |  ( (/ "
                    "/| |_) ) "
                    "|_| | |_| | |__   |___ | |_| |___ | |_( (/ /| | | |")
                    CRLF RED_STR(
                        "|______/ \\______|_______)______(_____)  | ||_/|_|   "
                        "\\____)____/ \\___/ \\___/ \\___)  (___/ \\__  (___/ "
                        "\\___)____)_|_|_|")
                        CRLF RED_STR("                                        "
                                     "|_|                   "
                                     "                          (____/         "
                                     "             ") CRLF CRLF;

static void init_crypto(void)
{
    ltc_mp = ltm_desc;
    register_all_ciphers();
    register_all_hashes();
}

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, void *x4)
{
    // Initialize malloc heap
    kalloc_init();

    // Initialize crypto
    init_crypto();

    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    // Print the header
    kputs(preboot_header);

    // Verify encrypted bootloader signature
    kputs("BULBIboot signature verification: ");
    verify_pflash(x4);
    kputs(GREEN_STR("OK") CRLF);

    bool aes_valid = false;
    unsigned char aes_key[AES256_KEY_LEN] = { 0 };
    unsigned char aes_key_hex[AES256_KEY_LEN * 2] = { 0 };
    do
    {
        // Ask for the bootloader AES key
        kputs("Enter BULBIboot decryption key (in hex format, e.g "
              "DEADB00F...): ");

        u8 read = 0;
        memset(aes_key_hex, 0, AES256_KEY_LEN);
        while (read < sizeof(aes_key_hex) + 1)
        {
            char c[] = { kgetc(), 0 };
            if (*c == '\r' || *c == '\n')
            {
                kputs(CRLF);
                break;
            }

            if (is_hex(c))
            {
                aes_key_hex[read++] = *c;
                kputc(*c);
            }
        }

        // Convert the key from hex to binary
        for (u8 i = 0; i < AES256_KEY_LEN; i++)
        {
            char c[] = { aes_key_hex[i * 2], aes_key_hex[i * 2 + 1], 0 };
            aes_key[i] = hextoi64(c);
        }

        aes_valid = verify_bootloader_aes_key(aes_key);
        if (aes_valid)
            kputs(GREEN_STR("Decryption key is valid, starting decryption...")
                      CRLF);
        else
            kputs(RED_STR("Invalid decryption key, try again...") CRLF);

    } while (!aes_valid);

    // Decrypt bootloader
    kputs("BULBIboot decryption: ");
    decrypt_pflash(x4, aes_key);
    kputs(GREEN_STR("OK") CRLF);

    // Jump to decrypted bootloader
    kputs("Jumping to BULBIboot" CRLF);
    void (*bootloader)(u64, u64, u64, u64, void *) =
        (void (*)(u64, u64, u64, u64, void *))(unsigned char *)x4
        + BOOTLOADER_BIN_ADDR;
    bootloader(x0, x1, x2, x3, x4);
}
