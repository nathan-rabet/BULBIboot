#include "memtest.h"

#include "console.h"
#include "kstring.h"
#include "number.h"
#include "uart.h"
#include "virt.h"

#define MEMTEST_VALUE_1 0x69UL
#define MEMTEST_VALUE_2 0xB0UL

static u64 memtest_shift_errors = 0;
static u64 memtest_xor_errors = 0;
static u64 memtest_bitwise_errors = 0;
static u64 memtest_add_errors = 0;
static u64 memtest_sub_errors = 0;

static void set(void *addr, u64 value, u8 granularity)
{
    switch (granularity)
    {
    case 1:
        *(u8 *)addr = value;
        break;
    case 2:
        *(u16 *)addr = value;
        break;
    case 4:
        *(u32 *)addr = value;
        break;
    case 8:
        *(u64 *)addr = value;
        break;
    default:
        kputs(CRLF "Invalid granularity" CRLF);
        return;
    }
}

static u64 get(void *addr, u8 granularity)
{
    switch (granularity)
    {
    case 1:
        return *(u8 *)addr;
    case 2:
        return *(u16 *)addr;
    case 4:
        return *(u32 *)addr;
    case 8:
        return *(u64 *)addr;
    default:
        kputs(CRLF YELLOW_STR("Invalid granularity") CRLF);
        return 0;
    }
}

static void reset_memtest_errors(void)
{
    memtest_shift_errors = 0;
    memtest_xor_errors = 0;
    memtest_add_errors = 0;
    memtest_sub_errors = 0;
}

static void memtest_shift(void *addr, u8 granularity)
{
    // Left shift
    set(addr, 1UL, granularity);
    for (u8 i = 0; i < 8 * granularity; i++)
    {
        if (get(addr, granularity) != (1UL << i))
            memtest_shift_errors++;
        set(addr, get(addr, granularity) << 1, granularity);
    }

    // Right shift
    set(addr, 0x80UL, granularity);
    for (u8 i = 0; i < 8 * granularity; i++)
    {
        if (get(addr, granularity) != (0x80UL >> i))
            memtest_shift_errors++;
        set(addr, get(addr, granularity) >> 1, granularity);
    }
}

static void memtest_xor(char *addr, u8 granularity)
{
    set(addr, MEMTEST_VALUE_1, granularity);
    set(addr, get(addr, granularity) ^ MEMTEST_VALUE_2, granularity);
    memtest_xor_errors +=
        get(addr, granularity) != (MEMTEST_VALUE_1 ^ MEMTEST_VALUE_2);

    set(addr, get(addr, granularity) ^ MEMTEST_VALUE_2, granularity);
    memtest_xor_errors += get(addr, granularity) != MEMTEST_VALUE_1;
}

static void memtest_bitwise(char *addr, u8 granularity)
{
    for (u64 i = 0; i < granularity; i++)
    {
        set(addr, 0, granularity);
        set(addr + i, 0xff, 1);
        memtest_bitwise_errors += get(addr, granularity) != (0xffUL << (i * 8));
    }
}

static void memtest_add(char *addr, u8 granularity)
{
    set(addr, 0, granularity);
    for (u64 i = 0; i < 0xff; i++)
    {
        set(addr, get(addr, granularity) + 1, granularity);
        memtest_add_errors += get(addr, granularity) != i + 1;
    }
}

static void memtest_sub(char *addr, u8 granularity)
{
    set(addr, 0xff, granularity);
    for (u64 i = 0; i < 0xff; i++)
    {
        set(addr, get(addr, granularity) - 1, granularity);
        memtest_sub_errors += get(addr, granularity) != 0xff - i - 1;
    }
}

extern u64 STACK_TOP;
#define STACK_TOP_ADDR ((void *)&STACK_TOP)
#define UART_CHECK_ITER 1000
void memtest(u64 base_addr, u64 size, u8 granularity)
{
    // Check the granularity
    switch (granularity)
    {
    case 1:
    case 2:
    case 4:
    case 8:
        break;
    default:
        kputs(CRLF YELLOW_STR("Invalid granularity for memtest") CRLF);
        kputs("Must be 1, 2, 4 or 8" CRLF);
        return;
    }

    u64 tmp;
    if (__builtin_add_overflow(base_addr, RAM_START, &base_addr)
        || __builtin_add_overflow(base_addr, size, &tmp))
    {
        kputs(CRLF RED_STR("Overflow detected, aborting...") CRLF);
        return;
    }

    if (base_addr + size > RAM_START + RAM_SIZE)
    {
        kputs(CRLF YELLOW_STR("Range is too big, aborting...") CRLF);
        return;
    }

    kputs(CRLF "Testing memory from ");
    kputs(itoa64hex(base_addr));
    kputs(" to ");
    kputs(itoa64hex(base_addr + size));
    kputs(" with granularity ");
    kputs(itoa64(granularity));
    kputs(CRLF CRLF);
    kputs("Press 'q' to abort" CRLF);

    // Reset the errors
    reset_memtest_errors();

    // UART 'q' buffer
    unsigned char quit = 0;

    // Test the memory
    for (char *addr = (char *)base_addr; (u64)addr < base_addr + size;
         addr += granularity)
    {
        // Each UART_CHECK_ITER iterations, check UART
        if (((u64)addr - base_addr) % (UART_CHECK_ITER * granularity) == 0)
        {
            // Check if there is something in the UART buffer
            if (uart_read(&quit, sizeof(unsigned char),
                          (volatile uart_t *)UART0_ADDR)
                > 0)
            {
                // If the user pressed 'q', abort the test
                if (quit == 'q')
                {
                    kputs(CRLF "Aborting..." CRLF);
                    break;
                }
            }
        }

        // Skip [TEXT_START, STACK_TOP_ADDR]
        if ((u64)addr >= TEXT_START && (u64)addr <= (u64)STACK_TOP_ADDR)
        {
            kputs(YELLOW_STR("\rSkipping [TEXT_START, STACK_TOP] range...")
                      CRLF);
            addr = STACK_TOP_ADDR;
            continue;
        }

        memtest_xor(addr, granularity);
        memtest_shift(addr, granularity);
        memtest_bitwise(addr, granularity);
        memtest_add(addr, granularity);
        memtest_sub(addr, granularity);

        // Printing the progress, reset the cursor
        kputs("\r");
        kputs(itoa64hex((u64)base_addr));
        kputs(" -> [");
        kputs("\033[34m");
        kputs(itoa64hex((u64)addr));
        kputs("\033[0m");
        kputs("] -> ");
        kputs(itoa64hex(base_addr + size));
    }

    kputs(CRLF GREEN_STR("Memory test finished successfully!") CRLF);

    // Print the results
    kputs(CRLF "RESULTS" CRLF);
    kputs("--------------------------------" CRLF CRLF);
    kputs("\tXOR errors:\t");
    kputs(itoa64(memtest_xor_errors));
    kputs(CRLF "\tSHIFT errors:\t");
    kputs(itoa64(memtest_shift_errors));
    kputs(CRLF "\tBITWISE errors:\t");
    kputs(itoa64(memtest_bitwise_errors));
    kputs(CRLF "\tADD errors:\t");
    kputs(itoa64(memtest_add_errors));
    kputs(CRLF "\tSUB errors:\t");
    kputs(itoa64(memtest_sub_errors));
    kputs(CRLF CRLF);
}
