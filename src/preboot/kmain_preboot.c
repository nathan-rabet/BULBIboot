#include "console.h"
#include "crypto.h"
#include "kalloc.h"
#include "kassert.h"
#include "kstring.h"
#include "number.h"
#include "preboot.h"
#include "prompt.h"
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

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, void *x4)
{
    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    // Print the header
    kputs(preboot_header);

    // Initialize malloc heap
    kputs("Initializing heap... " CRLF);
    kalloc_init();

    // Initialize crypto
    kputs("Initializing cryptographic library..." CRLF);
    init_crypto();

    // Verify encrypted bootloader signature
    kputs("BULBIboot signature verification: ");
    if (verify_bootloader(x4 + BOOTLOADER_IMG_OFFSET))
        kputs(GREEN_STR("OK") CRLF);
    else
    {
        kputs(RED_STR("FAILED") CRLF);
        panic("BULBIboot signature verification failed");
    }

    // Setup console prefix
    set_console_prefix("BULBIpreboot (decryption key) " RED_STR(">") " ");

    bool aes_valid = false;
    unsigned char aes_key[AES256_KEY_LEN];

    // Ask for the bootloader AES key
    kputs(BLUE_STR("Enter BULBIboot decryption key (in hex format, e.g "
                   "'DEADB00F'...): ") CRLF CRLF);
    do
    {
        memset(aes_key, 0, AES256_KEY_LEN);

        char *aes_key_hex = prompt();

        // Convert the key from hex to binary
        for (u8 i = 0; i < AES256_KEY_LEN; i++)
        {
            char c[] = { aes_key_hex[i * 2], aes_key_hex[i * 2 + 1], 0 };

            if (!is_hex(c))
                break;
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
    decrypt_bootloader(x4 + BOOTLOADER_IMG_OFFSET, aes_key);
    kputs(GREEN_STR("OK") CRLF);

    // Jump to decrypted bootloader
    kputs("Jumping to BULBIboot" CRLF);
    void (*bootloader)(u64, u64, u64, u64, void *) =
        (void (*)(u64, u64, u64, u64, void *))(unsigned char *)x4
        + BOOTLOADER_IMG_OFFSET;
    bootloader(x0, x1, x2, x3, x4);
}
