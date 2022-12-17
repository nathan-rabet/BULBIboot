#include "asm.h"
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

#define BUF_SIZE 1024

#define CRLF "\r\n"
#define PIKABOOT_CONSOLE() kputs(CRLF "PIKABROUT $ ")

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, u64 x4)
{
    linux_set_dtb_addr((void *)x0);
    (void)x1;
    (void)x2;
    (void)x3;
    linux_set_kernel_addr((char *)x4 + 0x3200000);

    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    // Initialize malloc heap
    kalloc_init();

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
                kputs("\t\tUsage: md <start address> <range> <load size>" CRLF);
                kputs("\tmemtest\t\tRun a memory test" CRLF);
                kputs("\t\tUsage: memtest [<start address> <range> "
                      "<granularity>]" CRLF);
                kputs(
                    "\temergency_boot\tDownload the firmware using the "
                    "serial port (via the kermin protocol) and boot it." CRLF);
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
