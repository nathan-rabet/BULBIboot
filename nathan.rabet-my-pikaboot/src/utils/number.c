#include "number.h"

#include "kassert.h"
#include "kstring.h"

#define BUF_SIZE 64

int is_hex(char *s)
{
    if (s[0] == '0' && s[1] == 'x')
        s += 2;

    for (size_t i = 0; i < tokenlen(s, " "); i++)
    {
        if (s[i] >= '0' && s[i] <= '9')
            continue;
        if (s[i] >= 'a' && s[i] <= 'f')
            continue;
        if (s[i] >= 'A' && s[i] <= 'F')
            continue;
        return 0;
    }

    return 1;
}

int is_int(char *s)
{
    for (size_t i = 0; i < tokenlen(s, " "); i++)
    {
        if (s[i] >= '0' && s[i] <= '9')
            continue;
        return 0;
    }

    return 1;
}

int is_number(char *s)
{
    return is_int(s) || is_hex(s);
}

char *itoa64(u64 n)
{
    static char buf[BUF_SIZE] = { 0 };
    char *p = buf + sizeof(buf) - 1;
    *p = '\0';
    do
    {
        *--p = '0' + (n % 10);
        n /= 10;
    } while (n);
    return p;
}

char *itoa64hex(u64 n)
{
    static char buf[BUF_SIZE] = { '0', 'x' };
    char *p = buf + sizeof(buf) - 1;
    *p = '\0';
    do
    {
        *--p = "0123456789abcdef"[n % 16];
        n /= 16;
    } while (n);

    // Copy at the beginning of the buffer
    char *p2 = buf + 2;
    while (*p)
        *p2++ = *p++;
    *p2 = '\0';
    return buf;
}

char *itoa64hex_no0x(u64 n)
{
    char *buf = itoa64hex(n);
    return buf + 2;
}

char *itoa64hex_no0x_ptr(void *addr, u8 size)
{
    u64 n = 0;
    switch (size)
    {
    case sizeof(u8):
        n = *(u8 *)addr;
        break;
    case sizeof(u16):
        n = *(u16 *)addr;
        break;
    case sizeof(u32):
        n = *(u32 *)addr;
        break;
    case sizeof(u64):
        n = *(u64 *)addr;
        break;
    default:
        kassert(0);
    }
    return itoa64hex_no0x(n);
}

u64 atoi64(char *s)
{
    u64 n = 0;
    for (size_t i = 0; i < tokenlen(s, " "); i++)
    {
        n *= 10;
        n += s[i] - '0';
    }
    return n;
}

u64 hextoi64(char *s)
{
    // Skip 0x if any
    if (s[0] == '0' && s[1] == 'x')
        s += 2;

    u64 n = 0;
    for (size_t i = 0; i < tokenlen(s, " "); i++)
    {
        n *= 16;
        if (s[i] >= '0' && s[i] <= '9')
            n += s[i] - '0';
        else if (s[i] >= 'a' && s[i] <= 'f')
            n += s[i] - 'a' + 10;
        else if (s[i] >= 'A' && s[i] <= 'F')
            n += s[i] - 'A' + 10;
    }

    return n;
}

u64 numtoi64(char *s)
{
    if (s[0] == '0' && s[1] == 'x')
        return hextoi64(s + 2);
    return atoi64(s);
}

char *aligned_numtoi64(char *s, u8 nb_digit)
{
    static char buf[BUF_SIZE] = { 0 };
    size_t buf_i = 0;

    kassert(nb_digit < BUF_SIZE);

    if (s[0] == '0' && s[1] == 'x')
    {
        s += 2;
        buf[buf_i++] = '0';
        buf[buf_i++] = 'x';
    }

    u64 len = tokenlen(s, " ");

    // Fill with 0
    if (nb_digit > len)
        for (u64 i = 0; i < nb_digit - len; i++)
            buf[buf_i++] = '0';

    // Copy the string
    for (u64 i = 0; i < len; i++)
        buf[buf_i++] = s[i];

    buf[buf_i++] = '\0';

    return buf;
}
