#include "asm.h"
#include "emergency_boot.h"
#include "int.h"
#include "kassert.h"
#include "kmalloc.h"
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
    // Setup UART0
    pl011_setup((volatile uart_t *)UART0_ADDR);

    alloc_init();
    // Malloc test
    char *ptr = malloc(0x1000);
    kputs("Malloc test");
    kassert(ptr != NULL);
    kputs(CRLF);

    // Write to the memory
    kputs("Writing to the memory");
    char string[] = "Malloc test";
    memcpy(ptr, string, sizeof(string));
    kassert(strcmp(ptr, string) == 0);
    kputs(CRLF);

    // Allocate a new memory
    char *ptr2 = malloc(0x1000);
    kputs("Allocating a new memory");
    kassert(ptr2 != NULL);
    kassert(ptr2 != ptr);
    kputs(CRLF);

    // Write on the new memory
    kputs("Writing on the new memory");
    char string2[] = "NEW Malloc test";
    memcpy(ptr2, string2, sizeof(string2));
    kassert(strcmp(ptr2, string2) == 0);
    kputs(CRLF);

    // Verify the first memory
    kputs("Verifying the first memory");
    kassert(strcmp(ptr, string) == 0);
    kputs(CRLF);

    // Free the memory
    kputs("Freeing the memory");
    free(ptr);
    free(ptr2);
    kputs(CRLF);

    // Reallocate the memory
    kputs("Reallocating the memory");
    char *ptr3 = malloc(0x1000);
    kassert(ptr3 != NULL);
    kassert(ptr3 == ptr);

    // Write on the reallocated memory
    kputs("Writing on the reallocated memory");
    char string3[] = "REALLOC Malloc test";
    memcpy(ptr3, string3, sizeof(string3));
    kassert(strcmp(ptr3, string3) == 0);
    kputs(CRLF);

    // Free the memory
    kputs("Freeing the memory");
    free(ptr3);

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
