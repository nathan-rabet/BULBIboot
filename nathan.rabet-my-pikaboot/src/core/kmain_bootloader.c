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
#include "prompt.h"
#include "uart.h"
#include "virt.h"

void kmain(void *x0, u64 x1, u64 x2, u64 x3, char *x4)
{
    // Initialize malloc heap
    kalloc_init();

    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    linux_set_dtb_addr(x0);
    (void)x1;
    (void)x2;
    (void)x3;
    linux_set_kernel_addr(x4 + 0x3200000);

    // Console input buffer
    set_console_prefix("BULBIboot"
                       " " BLUE_STR(">") " ");

    print_bulbiboot_header();

    while (true)
    {
        char *buf = prompt();

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
            kputs(
                "\t" BLUE_STR("emergency_boot") "\tDownload a kernel on the "
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

            char *start_addr =
                strtok_r(buf + sizeof("memtest") - 1, " ", &buf_tok);
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
                if (!is_number((char *)start_addr) || !is_number((char *)size)
                    || !is_number((char *)granularity))
                {
                    kputs(RED_STR("Invalid arguments") CRLF);
                }
                else
                {
                    start_addr = (char *)numtoi64(start_addr);
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
    }
}
