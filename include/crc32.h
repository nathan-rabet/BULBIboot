#ifndef CRC32_H
#define CRC32_H

#include "int.h"
#include <stddef.h>

extern const u32 crc32_tab[];

/**
 * Calculate CRC32 checksum of a buffer.
 *
 * @param buf   Buffer to calculate checksum of.
 * @param size  Size of the buffer.
 * @return      CRC32 checksum of the buffer.
 */
u32 crc32(const void *buf, size_t size);

#endif /* CRC32_H */
