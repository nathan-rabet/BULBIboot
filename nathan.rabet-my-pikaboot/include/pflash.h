#ifndef PFLASH_H
#define PFLASH_H

#include <stdbool.h>

#ifndef BOOTLOADER_BIN_OFFSET_MB
#    define BOOTLOADER_BIN_ADDR 0x0
#    error "BOOTLOADER_BIN_OFFSET_MB not defined"
#else
#    define BOOTLOADER_BIN_ADDR (BOOTLOADER_BIN_OFFSET_MB * 1024 * 1024)
#endif

#ifndef BOOTLOADER_BIN_LEN
#    define BOOTLOADER_BIN_LEN 0x0
#    error "BOOTLOADER_BIN_LEN not defined"
#endif

/**
 * @brief Verify the pflash integrity (signature)
 *
 * @param pflash_start The start address of the pflash
 *
 * @note This function panics if the pflash is not valid
 */
void verify_pflash(void *pflash_start);

/**
 * @brief Verify the bootloader AES key
 *
 * @param bootloader_aes_key The AES key to use for the pflash decryption
 *
 * @return bool True if the key is valid, false otherwise
 */
bool verify_bootloader_aes_key(const unsigned char *bootloader_aes_key);

/**
 * @brief Decrypt the pflash
 *
 * @param pflash_start The start address of the pflash
 * @param bootloader_aes_key The AES key to decrypt the pflash
 *
 * @note This function panics if the pflash is not valid
 */
void decrypt_pflash(void *pflash_start,
                    const unsigned char *bootloader_aes_key);

#endif /* PFLASH_H */
