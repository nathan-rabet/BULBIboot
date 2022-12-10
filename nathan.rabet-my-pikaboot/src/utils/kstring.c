#include "kstring.h"

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
    while (--n && *first && *second && *first == *second)
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

char *strtok(char *str, const char *delim)
{
    static char *last;
    return strtok_r(str, delim, &last);
}

char *strtok_r(char *str, const char *delim, char **last)
{
    if (str == NULL)
        str = *last;
    str += strspn(str, delim);
    if (*str == '\0')
        return NULL;
    *last = str + strcspn(str, delim);
    if (**last != '\0')
        *((*last)++) = '\0';
    else
        *last = NULL;
    return str;
}

size_t strspn(const char *str, const char *accept)
{
    const char *p;
    const char *a;
    size_t count = 0;

    for (p = str; *p != '\0'; ++p)
    {
        for (a = accept; *a != '\0'; ++a)
        {
            if (*p == *a)
                break;
        }
        if (*a == '\0')
            return count;
        else
            ++count;
    }
    return count;
}

size_t strcspn(const char *str, const char *reject)
{
    const char *p;
    const char *r;
    size_t count = 0;

    for (p = str; *p != '\0'; ++p)
    {
        for (r = reject; *r != '\0'; ++r)
        {
            if (*p == *r)
                return count;
        }
        ++count;
    }
    return count;
}

char *strchr(const char *str, int c)
{
    while (*str && *str != (char)c)
        str++;
    if (*str == (char)c)
        return (char *)str;
    return NULL;
}

size_t strlen(const char *str)
{
    size_t len = 0;
    while (str[len])
        len++;
    return len;
}

size_t tokenlen(const char *str, const char *delim)
{
    size_t len = 0;
    while (str[len] && !strchr(delim, str[len]))
        len++;
    return len;
}

void *memmove(void *dest, const void *src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;
    if (d < s)
    {
        while (n--)
            *d++ = *s++;
    }
    else
    {
        const unsigned char *lasts = s + (n - 1);
        unsigned char *lastd = d + (n - 1);
        while (n--)
            *lastd-- = *lasts--;
    }
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    while (n--)
    {
        if (*p1 != *p2)
            return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}
