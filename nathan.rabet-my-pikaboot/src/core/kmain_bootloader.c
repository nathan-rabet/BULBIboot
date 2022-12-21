#include <stddef.h>
#include <tomcrypt.h>

#include "asm.h"
#include "console.h"
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

#define BUF_SIZE 1024
#define NB_HISTORY 10

#define BULBIBOOT_CONSOLE() kputs(CRLF "BULBIboot" BLUE_STR(">") " ")

static u32 buf_i = 0;
static char buf[BUF_SIZE] = { 0 };

static u8 history_i = 0;
static u8 history_nb = 0;
static u8 up_key_counter = 0;
static char history[NB_HISTORY][BUF_SIZE] = { 0 };

static void get_history_line(u8 up_key_counter)
{
    if (history[(history_i - up_key_counter) % history_nb][0] != '\0')
    {
        for (u32 i = 0; i < buf_i; i++)
            kputs("\b \b");
        kputs(history[(history_i - up_key_counter) % history_nb]);
        strcpy(buf, history[(history_i - up_key_counter) % history_nb]);

        buf_i = strlen(buf);
        up_key_counter++;
    }
}

void kmain(u64 x0, u64 x1, u64 x2, u64 x3, u64 x4)
{
    // Initialize malloc heap
    kalloc_init();

    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    linux_set_dtb_addr((void *)x0);
    (void)x1;
    (void)x2;
    (void)x3;
    linux_set_kernel_addr((char *)x4 + 0x3200000);

    // Console input buffer

    // Print the header
    print_bulbiboot_header();
    BULBIBOOT_CONSOLE();
    while (true)
    {
        unsigned char typed[3] = { 0 };
        while (uart_read(typed, sizeof(typed), (volatile uart_t *)UART0_ADDR)
               == 0)
            ;

        // In case of newline
        if (typed[0] == '\r' || typed[0] == '\n')
        {
            if (strcmp("help", buf) == 0)
            {
                kputs(CRLF);
                kputs("This is BULBIboot, a simple bootloader for "
                      "aarch64" CRLF CRLF);
                kputs("AVAILABLE COMMANDS:" CRLF);
                kputs("\t" BLUE_STR("help") "\t\tDisplay this help" CRLF);
                kputs("\t" BLUE_STR("boot") "\t\tBoot the kernel" CRLF);
                kputs("\t" BLUE_STR("md") " \t\tDump memory" CRLF);
                kputs("\t\tUSAGE: md " YELLOW_STR(
                    "<start address> <range> <load size>") CRLF);
                kputs("\t\tNOTE: " YELLOW_STR(
                    "<start address>") " starts at 0x0" CRLF);
                kputs("\t\t" RED_STR(
                    "CAUTION: This command can crash the system if you specify "
                    "a non-readable address space") CRLF);
                kputs("\t" BLUE_STR("memtest") "\t\tRun a memory test" CRLF);
                kputs("\t\tUSAGE: memtest " YELLOW_STR(
                    "[<start address> <range> <granularity>]") CRLF);
                kputs("\t\tNOTE: " YELLOW_STR(
                    "<start address>") " starts at RAM_START (");
                kputs(itoa64hex(RAM_START));
                kputs(")" CRLF);
                kputs("\t" BLUE_STR(
                    "emergency_boot") "\tDownload a kernel on the "
                                      "serial port (using the "
                                      "emergency_server.py protocol) "
                                      "and boot on it" CRLF);
            }

            else if (strncmp("md", buf, 2) == 0)
            {
                kputs(CRLF);
                char *buf_tok = NULL;

                u64 start_addr = (u64)strtok_r(buf + 2, " ", &buf_tok);
                u64 range = (u64)strtok_r(NULL, " ", &buf_tok);
                u64 load_size = (u64)strtok_r(NULL, " ", &buf_tok);

                if (!is_number((char *)start_addr) || !is_number((char *)range)
                    || !is_number((char *)load_size))
                    kputs(RED_STR("Invalid arguments") CRLF);
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
                kputs(CRLF);
                kputs("Booting Linux..." CRLF);
                linux_boot();
            }

            else if (strncmp("memtest", buf, sizeof("memtest") - 1) == 0)
            {
                kputs(CRLF);
                char *buf_tok = NULL;

                u64 start_addr =
                    (u64)strtok_r(buf + sizeof("memtest") - 1, " ", &buf_tok);
                u64 size = (u64)strtok_r(NULL, " ", &buf_tok);
                u64 granularity = (u64)strtok_r(NULL, " ", &buf_tok);

                if (!start_addr)
                {
                    start_addr = 0;
                    size = RAM_SIZE;
                    granularity = 8;
                    memtest(start_addr, size, granularity);
                }
                else
                {
                    if (!is_number((char *)start_addr)
                        || !is_number((char *)size)
                        || !is_number((char *)granularity))
                    {
                        kputs(RED_STR("Invalid arguments") CRLF);
                    }
                    else
                    {
                        start_addr = numtoi64((char *)start_addr);
                        size = numtoi64((char *)size);
                        granularity = numtoi64((char *)granularity);
                        memtest(start_addr, size, granularity);
                    }
                }
            }

            else if (strcmp("emergency_boot", buf) == 0)
            {
                kputs(CRLF);
                kputs("Entering emergency boot..." CRLF);
                emergency_boot();
            }

            else if (strcmp("", buf) != 0)
            {
                kputs(CRLF);
                kputs(YELLOW_STR("Unknown command") CRLF);
            }

            if (buf_i > 0)
            {
                history_nb = MIN(history_nb + 1, NB_HISTORY);
                strcpy(history[history_i], buf);
                history_i = (history_i + 1) % NB_HISTORY;
            }

            up_key_counter = 0;

            // Reset buffer
            memset(buf, 0, BUF_SIZE);
            buf_i = 0;
            BULBIBOOT_CONSOLE();
        }

        // In case of deletion character
        else if (typed[0] == 0x7F)
        {
            if (buf_i > 0)
            {
                kputs("\b \b");
                buf[--buf_i] = '\0';
            }
        }

        // In case of left arrow
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x44)
        {
            if (buf_i > 0)
            {
                kputs("\b");
                buf_i--;
            }
        }

        // In case of right arrow
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x43)
        {
            if (buf_i < BUF_SIZE - 1 && buf[buf_i] != '\0')
                kputc(buf[buf_i++]);
        }

        // In case of up arrow (history up)
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x41)
        {
            if (up_key_counter + 1 <= history_nb)
                get_history_line(++up_key_counter);
        }

        // In case of down arrow (history down)
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x42)
        {
            if (up_key_counter <= 1) // up_key_counter - 1 <= 0 (overflow safe)
            {
                for (u32 i = 0; i < buf_i; i++)
                    kputs("\b \b");
                memset(buf, 0, BUF_SIZE);
                buf_i = 0;
                up_key_counter = 0;
            }
            else
                get_history_line(--up_key_counter);
        }

        // In case of printable character
        else if (buf_i < BUF_SIZE - 1 && typed[0] >= 0x20 && typed[0] <= 0x7E)
        {
            kputc(typed[0]);
            buf[buf_i++] = typed[0];
        }
    }
}
