#ifndef CRYPTO_H
#define CRYPTO_H

#define SHA512_DIGEST_SIZE 64

#include <stddef.h>

/**
 * @brief Compute the SHA512 hash of a buffer
 *
 * @note This function uses the tomcrypt library
 *
 * @param buf The buffer to hash
 * @param len The length of the buffer
 * @return char* The hash of the buffer (raw bytes)
 */
unsigned char *sha512(unsigned char *buf, size_t len);

/**
 * @brief Compute the SHA512 hash of a buffer and return it as a hex string
 *
 * @note This function uses the tomcrypt library
 *
 * @param buf The buffer to hash
 * @param len The length of the buffer
 * @return char* The hash of the buffer (hex string)
 */
char *sha512_hex(unsigned char *buf, size_t len);

#endif /* CRYPTO_H */
