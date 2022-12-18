// Implement a first-fit malloc/free.

#include "kalloc.h"

#include <stdbool.h>

#include "kassert.h"
#include "kstring.h"

typedef struct
{
    bool used;
    size_t size;
    char block[];
} alloc_node_t;

#define ALLOC_HEADER_SZ offsetof(alloc_node_t, block)

static alloc_node_t alloc_list;
bool is_init = false;

void kalloc_init(void)
{
    memset(&alloc_list, 0, HEAP_SIZE);
    alloc_list.size = HEAP_SIZE;
    is_init = true;
}

void *kmalloc(size_t size)
{
    kassert(is_init);

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

void kfree(void *ptr)
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

void *kcalloc(size_t nmemb, size_t size)
{
    // If there is an overflow, return NULL
    if (__builtin_mul_overflow(nmemb, size, &size))
        return NULL;

    void *ptr = kmalloc(size);
    if (ptr != NULL)
        memset(ptr, 0, size);
    return ptr;
}

void *krealloc(void *ptr, size_t size)
{
    if (ptr == NULL)
        return kmalloc(size);

    if (size == 0)
    {
        kfree(ptr);
        return NULL;
    }

    alloc_node_t *alloc_node = (alloc_node_t *)((char *)ptr - ALLOC_HEADER_SZ);

    if (alloc_node->size >= size)
        return ptr;

    void *new_ptr = kmalloc(size);
    if (new_ptr == NULL)
        return NULL;

    memcpy(new_ptr, ptr, alloc_node->size);
    kfree(ptr);
    return new_ptr;
}
