#include "kstring.h"

// Do not optimize this function
#pragma GCC push_options
#pragma GCC optimize("O0")
void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--)
        *p++ = c;
    return s;
}
#pragma GCC pop_options

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

#pragma GCC push_options
#pragma GCC optimize("O0")
void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}
#pragma GCC pop_options

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

char *strncpy(char *dest, const char *src, size_t n)
{
    char *ret = dest;
    while (n && (*dest++ = *src++))
        n--;
    if (n)
        while (--n)
            *dest++ = '\0';
    return ret;
}

// qsort
static void swap(unsigned char *a, unsigned char *b, size_t size)
{
    char tmp;
    while (size--)
    {
        tmp = *a;
        *a++ = *b;
        *b++ = tmp;
    }
}

static unsigned char *med3(unsigned char *a, unsigned char *b, unsigned char *c,
                           int (*cmp)(const void *, const void *))
{
    return cmp(a, b) < 0 ? (cmp(b, c) < 0 ? b : (cmp(a, c) < 0 ? c : a))
                         : (cmp(b, c) > 0 ? b : (cmp(a, c) < 0 ? a : c));
}

static void insertion_sort(unsigned char *a, size_t n, size_t size,
                           int (*cmp)(const void *, const void *))
{
    unsigned char *pi, *pj;
    for (pi = a + size; pi < a + n * size; pi += size)
        for (pj = pi; pj > a && cmp(pj - size, pj) > 0; pj -= size)
            swap(pj, pj - size, size);
}

void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *))
{
    unsigned char *a = base;
    unsigned char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
    size_t d, r;
    int cmp_result;

loop:
    if (nmemb < 7)
    {
        insertion_sort(a, nmemb, size, compar);
        return;
    }
    pm = a + (nmemb / 2) * size;
    if (nmemb > 7)
    {
        pl = a;
        pn = a + (nmemb - 1) * size;
        if (nmemb > 40)
        {
            d = (nmemb / 8) * size;
            pl = med3(pl, pl + d, pl + 2 * d, compar);
            pm = med3(pm - d, pm, pm + d, compar);
            pn = med3(pn - 2 * d, pn - d, pn, compar);
        }
        pm = med3(pl, pm, pn, compar);
    }
    swap(a, pm, size);
    pa = pb = a + size;

    pc = pd = a + (nmemb - 1) * size;
    for (;;)
    {
        while (pb <= pc && (cmp_result = compar(pb, a)) <= 0)
        {
            if (cmp_result == 0)
            {
                swap(pa, pb, size);
                pa += size;
            }
            pb += size;
        }
        while (pb <= pc && (cmp_result = compar(pc, a)) >= 0)
        {
            if (cmp_result == 0)
            {
                swap(pc, pd, size);
                pd -= size;
            }
            pc -= size;
        }
        if (pb > pc)
            break;
        swap(pb, pc, size);
        pb += size;
        pc -= size;
    }

    pn = a + nmemb * size;
    r = MIN(pa - a, pb - pa);
    swap(a, pb - r, r);
    r = MIN((size_t)(pd - pc), pn - pd - size);
    swap(pb, pn - r, r);
    if ((r = pb - pa) > size)
        qsort(a, r / size, size, compar);
    if ((r = pd - pc) > size)
    {
        a = pn - r;
        nmemb = r / size;
        goto loop;
    }
}
