#include "memtest.h"

#include "kstring.h"
#include "number.h"
#include "uart.h"
#include "virt.h"

#ifndef RAM_SIZE_GB
#    define RAM_SIZE_GB 2
#endif

#define RAM_SIZE (RAM_SIZE_GB * 1024UL * 1024UL * 1024UL)

#define MEMTEST_VALUE_1 0x69UL
#define MEMTEST_VALUE_2 0xB0UL

static u64 memtest_shift_errors = 0;
static u64 memtest_xor_errors = 0;
static u64 memtest_byte_per_byte_errors = 0;
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
        kputs(CRLF "Invalid granularity" CRLF);
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

static void memtest_byte_per_byte(char *addr, u8 granularity)
{
    for (u64 i = 0; i < granularity; i++)
    {
        set(addr, 0, granularity);
        set(addr + i, 0xff, 1);
        memtest_byte_per_byte_errors +=
            get(addr, granularity) != (0xffUL << (i * 8));
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
        kputs(CRLF "Invalid granularity for memtest" CRLF);
        kputs("Must be 1, 2, 4 or 8" CRLF);
        return;
    }

    // Check if addr + size is in the RAM and if there is an overflow
    if (base_addr + size > RAM_SIZE && base_addr + size < base_addr)
    {
        kputs("Invalid memory range for memtest" CRLF);
        return;
    }

    kputs(CRLF "Testing memory from ");
    kputs(itoa64hex(RAM_START + base_addr));
    kputs(" to ");
    kputs(itoa64hex((RAM_START + base_addr) + size));
    kputs(" with granularity ");
    kputs(itoa64(granularity));
    kputs(CRLF);

    // Reset the errors
    reset_memtest_errors();

    // Test the memory
    for (char *addr = (char *)RAM_START + base_addr;
         (u64)addr < RAM_START + base_addr + size; addr += granularity)
    {
        memtest_xor(addr, granularity);
        memtest_byte_per_byte(addr, granularity);
        memtest_add(addr, granularity);
        memtest_sub(addr, granularity);
        memtest_shift(addr, granularity);

        // On each percent, print ONE dot
        if (((u64)addr - (RAM_START + base_addr)) % (size / 100) == 0)
            kputc('.');
    }

    // Print the results
    kputs(CRLF "Memtest results:" CRLF);
    kputs("\tShift errors: ");
    kputs(itoa64(memtest_shift_errors));
    kputs(CRLF "\tXOR errors: ");
    kputs(itoa64(memtest_xor_errors));
    kputs(CRLF "\tByte per byte errors: ");
    kputs(itoa64(memtest_byte_per_byte_errors));
    kputs(CRLF "\tAdd errors: ");
    kputs(itoa64(memtest_add_errors));
    kputs(CRLF "\tSub errors: ");
    kputs(itoa64(memtest_sub_errors));
}
