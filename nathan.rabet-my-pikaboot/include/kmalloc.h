#ifndef KMALLOC_H
#define KMALLOC_H

#include <stddef.h>

// 50 MB
#define HEAP_SIZE 52428800

/**
 * @brief Initialize the heap
 *
 */
void alloc_init(void);

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

#endif /* KMALLOC_H */
