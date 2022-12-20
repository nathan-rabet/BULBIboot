// Implement a first-fit malloc/free.

#include "kalloc.h"

#include "kassert.h"
#include "kstring.h"

#define ALLOC_HEADER_SZ offsetof(alloc_node_t, block)

#define OVERFLOW_ADDITIONNAL_SZ 1024

static bool is_init = false;
void kalloc_init(void)
{
    memset(HEAP_START_ADDR, 0, HEAP_SIZE);
    HEAP_START_ADDR->size = HEAP_SIZE;
    SET_ALLOC_NODE_CANARY(HEAP_START_ADDR);
    is_init = true;
}

void *kmalloc(size_t size)
{
    kassertm(is_init, "Heap is not initialized");

    if (size == 0)
        return NULL;

    size += OVERFLOW_ADDITIONNAL_SZ;
    for (alloc_node_t *curr = HEAP_START_ADDR; curr->size != 0;
         curr = (alloc_node_t *)((char *)curr->block + curr->size))
    {
        ALLOC_NODE_CANARY_INTEGRITY(curr);
        if (!curr->used && curr->size >= size)
        {
            // Modifying next adjacent node (if it is free)
            alloc_node_t *adj_next =
                (alloc_node_t *)((char *)curr->block + size);

            // Modifying next adjacent node (if it is free)
            if (adj_next->used == false)
            {
                SET_ALLOC_NODE_CANARY(adj_next);
                adj_next->size = curr->size - size;
            }
            else
            {
                ALLOC_NODE_CANARY_INTEGRITY(adj_next);
            }

            // Modifying current node
            curr->used = true;
            curr->size = size;

#ifdef DEBUG
            curr->next = (struct alloc_node_t *)adj_next;
#endif
            return curr->block;
        }
    }

    return NULL;
}

void kfree(void *ptr)
{
    if (ptr)
    {
        alloc_node_t *alloc_node =
            (alloc_node_t *)((char *)ptr - ALLOC_HEADER_SZ);
        ALLOC_NODE_CANARY_INTEGRITY(alloc_node);

        alloc_node->used = false;

        // Merge with next adjacent node if it is free
        alloc_node_t *adj_next =
            (alloc_node_t *)((char *)alloc_node->block + alloc_node->size);
        if (adj_next->used == false)
            alloc_node->size += adj_next->size;
    }
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
    ALLOC_NODE_CANARY_INTEGRITY(alloc_node);

    if (alloc_node->size >= size)
        return ptr;

    void *new_ptr = kmalloc(size);
    if (new_ptr == NULL)
        return NULL;

    memcpy(new_ptr, ptr, alloc_node->size);
    kfree(ptr);
    return new_ptr;
}
