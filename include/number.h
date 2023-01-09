#ifndef NUMBER_H
#define NUMBER_H

#include "int.h"

/**
 * @brief Check if a string is a hexadecimal number
 *
 * @param s The string to check
 * @return int 1 if it is a hexadecimal number, 0 otherwise
 */
int is_hex(char *s);

/**
 * @brief Check if a string is an integer
 *
 * @param s The string to check
 * @return int 1 if it is an integer, 0 otherwise
 */
int is_int(char *s);

/**
 * @brief Check if a string is a number
 *
 * @param s The string to check
 * @return int 1 if it is a number, 0 otherwise
 */
int is_number(char *s);

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

/**
 * @brief Convert a 64-bit integer to a string in hexadecimal (without the 0x)
 *
 * @param n The integer to convert
 * @return char* The string (without the 0x)
 */
char *itoa64hex_no0x(u64 n);

/**
 * @brief Convert a u8, u16, u32 or u64 to a string
 *
 * @param addr The address of the integer to convert
 * @param size The size of the integer to convert
 * @return char* The string
 */
char *itoa64hex_no0x_ptr(void *addr, u8 size);

/**
 * @brief Convert a string number base 10 to a 64-bit integer
 *
 * @param s The string (base 10)
 * @return u64 The integer
 */
u64 atoi64(char *s);

/**
 * @brief Convert a string number base 16 to a 64-bit integer
 *
 * @param s The string (base 16)
 * @return u64 The integer
 */
u64 hextoi64(char *s);

/**
 * @brief Convert a base 10 or base 16 string to a 64-bit integer
 *
 * @param n The integer to convert (if starts with 0x, base 16, else base 10)
 * @return u64 The integer
 */
u64 numtoi64(char *s);

/**
 * @brief Convert a string number base 10 or base 16 to a a string
 * with a certain number of digits
 *
 * @param s The string (base 10)
 * @param nb_digits The number of digits
 * @return char
 */
char *aligned_numtoi64(char *s, u8 nb_digit);

#endif /* NUMBER_H */
