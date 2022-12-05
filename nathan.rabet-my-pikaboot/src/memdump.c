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
    start_addr = RAM_START + start_addr - (start_addr % load_size);

    for (u64 i = 0; i < range; i += MEMDUMP_LINE_SIZE)
    {
        kputs(CRLF);

        // Left side: address
        kputs(aligned_numtoi64(itoa64hex(start_addr + i - RAM_START),
                               MEMDUMP_LINE_SIZE));
        kputs(":\t");

        // Middle side: print the memory as hex
        char line[MEMDUMP_LINE_SIZE] = { 0 };
        for (u8 j = 0; j < MEMDUMP_LINE_SIZE; j++)
        {
            char *addr = (char *)start_addr + i + j;
            if (i + j < range)
            {
                line[j] = *addr;
                kputs(aligned_numtoi64(itoa64hex_no0x_ptr(addr, sizeof(char)),
                                       sizeof(char) * 2));
            }
            else
                for (u8 k = 0; k < sizeof(char) * 2; k++)
                    kputc(' ');

            // Print a space each load_size
            if ((j + 1) % load_size == 0)
                kputc(' ');
        }

        kputs("\t| ");

        // Right side: print the memory as ascii
        for (u8 i = 0; i < MEMDUMP_LINE_SIZE; i++)
        {
            // Printable characters
            if (line[i] >= 32 && line[i] <= 126)
                kputc(line[i]);
            else
                kputc('.');
        }
        kputs(" |");
    }
}
