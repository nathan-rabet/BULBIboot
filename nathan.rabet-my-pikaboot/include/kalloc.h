#ifndef KALLOC_H
#define KALLOC_H
#include <stdbool.h>
#include <stddef.h>

#include "int.h"

typedef struct alloc_node_t
{
    bool used;
    size_t size;
#ifdef DEBUG
    struct alloc_node_t *next;
#endif
    char block[];
} alloc_node_t;

extern u64 HEAP_START;
#define HEAP_START_ADDR ((alloc_node_t *)(&HEAP_START))
#define HEAP_SIZE (8 * 1024 * 1024) // 8 MiB

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
