#include "asm.h"
#include "debug.h"
#include "int.h"
#include "string.h"
#include "uart.h"

#define BUF_SIZE 1024

#define CRLF "\r\n"
#define PIKABOOT_CONSOLE() kputs(CRLF "pikaboot 3> ")

struct aarch64_registers
{
    u64 x[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

void bmain(u64 x0, u64 x1, u64 x2, u64 x3, u64 x4)
{
    u64 dtb = x0;
    u64 bmain_addr = x4;
    (void)x1;
    (void)x2;
    (void)x3;

    kputs("dtb: ");
    kputs(itoa64hex(dtb));
    kputs(CRLF);

    kputs("bmain: ");
    kputs(itoa64hex(bmain_addr));
    kputs(CRLF);

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
            if (strncmp("help", buf, buf_i + 1) == 0)
            {
                kputs(CRLF
                      "This is pikaboot, a simple bootloader for ARM64" CRLF);
            }

            else if (strncmp("boot", buf, buf_i + 1) == 0)
            {
                kputs(CRLF "Booting Linux..." CRLF);
                extern void linux_boot(u64, u64);
                linux_boot(dtb, bmain_addr);
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
                buf_i--;
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
