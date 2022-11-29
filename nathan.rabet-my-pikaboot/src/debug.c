#include "debug.h"

char *itoa64(u64 n)
{
    static char buf[64];
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
    static char buf[64] = { '0', 'x' };
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
