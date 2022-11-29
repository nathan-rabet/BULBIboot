#include "string.h"

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--)
        *p++ = c;
    return s;
}

int strcmp(const char *first, const char *second)
{
    while (*first && *second && *first == *second)
    {
        first++;
        second++;
    }
    return *first - *second;
}

int strncmp(const char *first, const char *second, size_t n)
{
    while (n-- && *first && *second && *first == *second)
    {
        first++;
        second++;
    }
    return *first - *second;
}

void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}
