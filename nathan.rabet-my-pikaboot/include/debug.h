#ifndef DEBUG_H
#define DEBUG_H

#include "int.h"

/**
 * @brief Convert a 64-bit integer to a string
 *
 * @param n The integer to convert
 * @return char* The string
 */
char *itoa64(u64 n);

/**
 * @brief Convert a 64-bit integer to a string in hexadecimal
 *
 * @param n The integer to convert
 * @return char* The string
 */
char *itoa64hex(u64 n);

#endif /* DEBUG_H */
