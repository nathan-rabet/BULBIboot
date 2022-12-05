#include "asm.h"
#include "int.h"
#include "kstring.h"
#include "memdump.h"
#include "number.h"
#include "uart.h"

#define BUF_SIZE 1024

#define CRLF "\r\n"
#define PIKABOOT_CONSOLE() kputs(CRLF "pikaboot 3> ")

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, u64 x4)
{
    u64 dtb = x0;
    u64 kmain_addr = x4;
    (void)x1;
    (void)x2;
    (void)x3;

    // Console input buffer
    char buf[BUF_SIZE] = { 0 };
    u32 buf_i = 0;

    PIKABOOT_CONSOLE();
    while (1)
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
                extern void linux_boot(u64, u64);
                linux_boot(dtb, kmain_addr);
            }

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