#ifndef KALLOC_H
#define KALLOC_H
#include <stdbool.h>
#include <stddef.h>

#include "int.h"

typedef struct alloc_node_t
{
    u64 coin;
    bool used;
    size_t size;
#ifdef DEBUG
    struct alloc_node_t *next;
#endif
    u64 coin_coin;
    char block[];
} __attribute__((packed)) alloc_node_t;

extern u64 STACK_TOP;
#define STACK_TOP_ADDR ((void *)&STACK_TOP)

extern alloc_node_t HEAP_START;
#define HEAP_START_ADDR (&HEAP_START)

// 20 MB
#define HEAP_SIZE (20 * 1024 * 1024)

#define SET_ALLOC_NODE_CANARY(node)                                            \
    node->coin = 0xdeadbeefdeadbeef;                                           \
    node->coin_coin = 0xbeefdeadbeefdead

#define ALLOC_NODE_CANARY_INTEGRITY(node)                                      \
    kassertm(node->coin == 0xdeadbeefdeadbeef, "Low canary is dead");          \
    kassertm(node->coin_coin == 0xbeefdeadbeefdead, "High canary is dead")

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
