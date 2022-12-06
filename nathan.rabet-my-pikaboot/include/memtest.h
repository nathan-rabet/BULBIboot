#ifndef MEMTEST_H
#define MEMTEST_H

#include "int.h"

/**
 * @brief Test the memory efficiency
 *
 * @param base_addr The base base_address of the memory to test
 * @param size The size of the memory to test
 * @param granularity The byte granularity of the test.
 * Can be 1, 2, 4 or 8.
 */
void memtest(u64 base_addr, u64 size, u8 granularity);

#endif /* MEMTEST_H */
