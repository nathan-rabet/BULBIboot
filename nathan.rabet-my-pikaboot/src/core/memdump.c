#include "memdump.h"

#include "kstring.h"
#include "number.h"
#include "uart.h"
#include "virt.h"

#define MEMDUMP_LINE_SIZE (sizeof(void *) * 2)

void memdump(u64 start_addr, u64 range, u64 load_size)
{
    // Check if load_size is valid
    switch (load_size)
    {
    case 1:
    case 2:
    case 4:
    case 8:
        break;
    default:
        kputs(CRLF "Invalid load size" CRLF);
        kputs("Valid load sizes are 1, 2, 4 and 8" CRLF);
        return;
    }

    // Align start_addr with load_size
    start_addr = start_addr - (start_addr % load_size);

    for (u64 i = 0; i < range; i += MEMDUMP_LINE_SIZE)
    {
        kputs(CRLF);

        // Left side: address
        kputs(aligned_numtoi64(itoa64hex(start_addr + i), MEMDUMP_LINE_SIZE));
        kputs(":\t");

        // Middle side: print the memory as hex
        char line[MEMDUMP_LINE_SIZE] = { 0 };
        for (u8 j = 0; j < MEMDUMP_LINE_SIZE; j += load_size)
        {
            char *addr = (char *)start_addr + i + j;
            if (i + j < range)
            {
                for (u8 k = 0; k < load_size; k++)
                    line[j + k] = addr[k];

                kputs(aligned_numtoi64(itoa64hex_no0x_ptr(addr, load_size),
                                       load_size * 2));
            }
            else
                for (u8 k = 0; k < load_size * 2; k++)
                    kputc(' ');

            kputc(' ');
        }

        kputs("| ");

        // Right side: print the memory as ascii
        for (u8 j = 0; j < MEMDUMP_LINE_SIZE; j++)
        {
            // Printable characters
            if (i + j < range)
                if (line[j] >= 32 && line[j] <= 126)
                    kputc(line[j]);
                else
                    kputc('.');
            else
                kputc(' ');
        }
        kputs(" |");
    }
}
