#ifndef STRING_H
#define STRING_H

#include <stddef.h>

#define CRLF "\r\n"

void *memset(void *s, int c, size_t n);

int strcmp(const char *first, const char *second);

int strncmp(const char *first, const char *second, size_t n);

void *memcpy(void *dest, const void *src, size_t n);

char *strtok(char *str, const char *delim);

char *strtok_r(char *str, const char *delim, char **last);

size_t strcspn(const char *str, const char *reject);

size_t strspn(const char *str, const char *accept);

char *strchr(const char *str, int c);

size_t strlen(const char *s);

void *memmove(void *dest, const void *src, size_t n);

size_t tokenlen(const char *str, const char *delim);

int memcmp(const void *s1, const void *s2, size_t n);

#endif /* STRING_H */
