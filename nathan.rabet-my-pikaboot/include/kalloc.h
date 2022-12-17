#ifndef KALLOC_H
#define KALLOC_H

#include <stddef.h>

// 50 MB
#define HEAP_SIZE 52428800

/**
 * @brief Initialize the heap
 *
 */
void kalloc_init(void);

void *kmalloc(size_t size);
void *kcalloc(size_t nmemb, size_t size);
void *krealloc(void *ptr, size_t size);
void kfree(void *ptr);

#endif /* KALLOC_H */
