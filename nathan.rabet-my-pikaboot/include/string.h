#ifndef STRING_H
#define STRING_H

#include <stddef.h>

void *memset(void *s, int c, size_t n);

int strcmp(const char *first, const char *second);

int strncmp(const char *first, const char *second, size_t n);

void *memcpy(void *dest, const void *src, size_t n);

#endif /* STRING_H */
