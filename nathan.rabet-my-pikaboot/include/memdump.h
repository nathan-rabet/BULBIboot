#ifndef MEMDUMP_H
#define MEMDUMP_H

#include "int.h"

/**
 * @brief Print the memory dump of a range of memory
 *
 * @param start_addr The start address
 * @param range The range to dump
 * @param load_size The size of the load (1, 2 or 4)
 */
void memdump(u64 start_addr, u64 range, u64 load_size);

#endif /* MEMDUMP_H */
