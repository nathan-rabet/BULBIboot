#include <stddef.h>
#include <tomcrypt.h>

#include "asm.h"
#include "crypto.h"
#include "emergency_boot.h"
#include "int.h"
#include "kalloc.h"
#include "kassert.h"
#include "kstring.h"
#include "linux_boot.h"
#include "memdump.h"
#include "memtest.h"
#include "number.h"
#include "uart.h"
#include "virt.h"

unsigned char rsa_public_key_der[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdf, 0xd5, 0xcb,
    0x86, 0x32, 0x07, 0x04, 0xe5, 0x27, 0x3d, 0xfa, 0xf0, 0x22, 0xa6, 0xef,
    0x8f, 0x3f, 0x7c, 0x4a, 0xd9, 0x60, 0x45, 0xc3, 0x6f, 0x5a, 0xc2, 0xe2,
    0x88, 0x42, 0x71, 0x09, 0xa8, 0xdf, 0xcd, 0x53, 0xf3, 0x8c, 0x06, 0xae,
    0xbb, 0xdc, 0x48, 0xba, 0x39, 0x0f, 0x19, 0x53, 0xa4, 0x1b, 0x22, 0xce,
    0xe8, 0xb6, 0x21, 0xfa, 0x20, 0x88, 0x36, 0x92, 0x4a, 0x1e, 0x98, 0xe2,
    0xde, 0xf9, 0xc7, 0xf4, 0xe4, 0xef, 0xa0, 0xa3, 0x60, 0x44, 0x9e, 0x88,
    0x0e, 0x6e, 0x51, 0x24, 0xf5, 0xb0, 0x52, 0xd7, 0xb3, 0x4e, 0xa8, 0x84,
    0xe8, 0x76, 0xe6, 0x3d, 0xc5, 0x60, 0x71, 0xc9, 0x3e, 0x71, 0x56, 0x7c,
    0x9c, 0xf5, 0x48, 0x88, 0xb0, 0x8f, 0x16, 0x41, 0xd2, 0x3c, 0xb0, 0x00,
    0x66, 0x34, 0x92, 0x77, 0xe5, 0x41, 0x36, 0x9e, 0x67, 0xf5, 0x83, 0x61,
    0xec, 0x89, 0x87, 0xdc, 0x87, 0x68, 0x64, 0x17, 0x12, 0x05, 0xcb, 0xb4,
    0xdb, 0x00, 0xa3, 0x46, 0x33, 0x91, 0xdd, 0xde, 0x22, 0x24, 0x59, 0x25,
    0x60, 0xc9, 0xf3, 0xe7, 0x8a, 0x81, 0xd2, 0xdf, 0x48, 0x63, 0x35, 0x2e,
    0xae, 0x9a, 0x56, 0xc0, 0x94, 0x30, 0xa2, 0x8e, 0xcc, 0xe0, 0x31, 0xf9,
    0xb5, 0xf4, 0xea, 0x53, 0x3b, 0x07, 0x93, 0xd3, 0x83, 0x6a, 0x14, 0x22,
    0x55, 0x2a, 0xfe, 0xc2, 0xcb, 0x87, 0x9c, 0xcd, 0xe5, 0x5b, 0x6c, 0x93,
    0xe3, 0x22, 0x55, 0xbd, 0x91, 0xe6, 0xc3, 0x5b, 0x4d, 0xfe, 0x1a, 0xa3,
    0x4b, 0x33, 0xf3, 0x29, 0xf4, 0xe5, 0xa3, 0x6f, 0x8b, 0x48, 0x59, 0xb4,
    0x98, 0x9b, 0xcd, 0xd0, 0xee, 0x94, 0x85, 0xcb, 0x24, 0x4e, 0xa6, 0x98,
    0x3e, 0x0b, 0x56, 0x48, 0x7b, 0x0b, 0xa6, 0x8b, 0x2d, 0xd6, 0x11, 0x5e,
    0x35, 0x43, 0xdc, 0xdd, 0xcd, 0x89, 0x98, 0x32, 0xcf, 0x63, 0xc8, 0x37,
    0x55, 0x02, 0x03, 0x01, 0x00, 0x01
};
#define BUF_SIZE 1024

#define CRLF "\r\n"
#define PIKABOOT_CONSOLE() kputs(CRLF "PIKABROUT $ ")

static void init_crypto(void)
{
    ltc_mp = ltm_desc;
    register_all_ciphers();
    register_all_hashes();
}

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, u64 x4)
{
    // Initialize malloc heap
    kalloc_init();

    // Initialize crypto
    init_crypto();

    // Test DER parsing
    rsa_key key;
    bool ret =
        parse_rsa_der(rsa_public_key_der, sizeof(rsa_public_key_der), &key);
    kassert(ret);

    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    linux_set_dtb_addr((void *)x0);
    (void)x1;
    (void)x2;
    (void)x3;
    linux_set_kernel_addr((char *)x4 + 0x3200000);

    // Console input buffer
    char buf[BUF_SIZE] = { 0 };
    u32 buf_i = 0;

    PIKABOOT_CONSOLE();
    while (true)
    {
        char c = kgetc();

        // In case of newline
        if (c == '\r' || c == '\n')
        {
            if (strcmp("help", buf) == 0)
            {
                kputs(CRLF
                      "This is pikaboot, a simple bootloader for ARM64" CRLF);
                kputs("Available commands:" CRLF);
                kputs("\thelp\t\tDisplay this help" CRLF);
                kputs("\tboot\t\tBoot the kernel" CRLF);
                kputs("\tmd \t\tDump memory" CRLF);
                kputs("\t\tUsage: md <start address> <range> <load "
                      "size>" CRLF);
                kputs("\tmemtest\t\tRun a memory test" CRLF);
                kputs("\t\tUsage: memtest [<start address> <range> "
                      "<granularity>]" CRLF);
                kputs("\temergency_boot\tDownload the firmware using the "
                      "serial port (via the kermin protocol) and boot "
                      "it." CRLF);
            }

            else if (strncmp("md", buf, 2) == 0)
            {
                char *buf_tok = NULL;

                u64 start_addr = (u64)strtok_r(buf + 2, " ", &buf_tok);
                u64 range = (u64)strtok_r(NULL, " ", &buf_tok);
                u64 load_size = (u64)strtok_r(NULL, " ", &buf_tok);

                if (!is_number((char *)start_addr) || !is_number((char *)range)
                    || !is_number((char *)load_size))
                    kputs(CRLF "Invalid arguments" CRLF);
                else
                {
                    start_addr = numtoi64((char *)start_addr);
                    range = numtoi64((char *)range);
                    load_size = numtoi64((char *)load_size);
                    memdump(start_addr, range, load_size);
                }
            }

            else if (strcmp("boot", buf) == 0)
            {
                kputs(CRLF "Booting Linux..." CRLF);
                linux_boot();
            }

            else if (strncmp("memtest", buf, 7) == 0)
            {
                char *buf_tok = NULL;

                u64 start_addr = (u64)strtok_r(buf + 7, " ", &buf_tok);
                u64 size = (u64)strtok_r(NULL, " ", &buf_tok);
                u64 granularity = (u64)strtok_r(NULL, " ", &buf_tok);

                if (!is_number((char *)start_addr) || !start_addr)
                    start_addr = RAM_START;
                else
                    start_addr = numtoi64((char *)start_addr);
                if (!is_number((char *)size) || !size)
                    size = 0x1000;
                else
                    size = numtoi64((char *)size);
                if (!is_number((char *)granularity) || !granularity)
                    granularity = 1;
                else
                    granularity = numtoi64((char *)granularity);

                memtest(start_addr, size, granularity);
            }

            else if (strcmp("emergency_boot", buf) == 0)
            {
                kputs(CRLF "Entering emergency boot..." CRLF);
                emergency_boot();
            }

            else
                kputs(CRLF "Unknown command" CRLF);

            // Reset buffer
            memset(buf, 0, BUF_SIZE);
            buf_i = 0;
            PIKABOOT_CONSOLE();
        }

        // In case of deletion character
        else if (c == 0x7F)
        {
            if (buf_i > 0)
            {
                kputs("\b \b");
                buf[--buf_i] = '\0';
            }
        }

        // In case of normal character
        else if (buf_i < BUF_SIZE - 1)
        {
            buf[buf_i++] = c;
            kputc(c);
        }
    }
}
