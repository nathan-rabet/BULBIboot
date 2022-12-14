// Implement a first-fit malloc/free.

#include "kmalloc.h"

#include <stdbool.h>

#include "kstring.h"

typedef struct
{
    bool used;
    size_t size;
    char block[];
} alloc_node_t;

#define ALLOC_HEADER_SZ offsetof(alloc_node_t, block)

static alloc_node_t alloc_list;
;

void alloc_init(void)
{
    memset(&alloc_list, 0, HEAP_SIZE);
    alloc_list.size = HEAP_SIZE;
}

void *malloc(size_t size)
{
    if (size == 0)
        return NULL;

    for (alloc_node_t *curr = &alloc_list;;
         curr = (alloc_node_t *)((char *)curr + curr->size))
    {
        if (!curr->used && curr->size >= size)
        {
            // Modifying next adjacent node (if it is free)
            alloc_node_t *adj_next = (alloc_node_t *)((char *)curr + size);
            if (adj_next->used == false)
                adj_next->size = curr->size - size;

            // Modifying current node
            curr->used = true;
            curr->size = size;
            return curr->block;
        }
    }

    return NULL;
}

void free(void *ptr)
{
    if (ptr == NULL)
        return;

    alloc_node_t *alloc_node = (alloc_node_t *)((char *)ptr - ALLOC_HEADER_SZ);

    alloc_node->used = false;

    // Merge with next adjacent node if it is free
    alloc_node_t *adj_next =
        (alloc_node_t *)((char *)alloc_node + alloc_node->size);
    if (adj_next->used == false)
        alloc_node->size += adj_next->size;
}

void *calloc(size_t nmemb, size_t size)
{
    // If there is an overflow, return NULL
    if (__builtin_mul_overflow(nmemb, size, &size))
        return NULL;

    void *ptr = malloc(size);
    if (ptr != NULL)
        memset(ptr, 0, size);
    return ptr;
}

void *realloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return malloc(size);

    if (size == 0)
    {
        free(ptr);
        return NULL;
    }

    alloc_node_t *alloc_node = (alloc_node_t *)((char *)ptr - ALLOC_HEADER_SZ);

    if (alloc_node->size >= size)
        return ptr;

    void *new_ptr = malloc(size);
    if (new_ptr == NULL)
        return NULL;

    memcpy(new_ptr, ptr, alloc_node->size);
    free(ptr);
    return new_ptr;
}
