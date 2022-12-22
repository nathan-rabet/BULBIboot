#ifndef PREBOOT_H
#define PREBOOT_H

#include <stdbool.h>

#ifndef BOOTLOADER_IMG_OFFSET
#    error "BOOTLOADER_IMG_OFFSET not defined"
#endif

#ifndef BOOTLOADER_IMG_LEN
#    error "BOOTLOADER_IMG_LEN not defined"
#endif

/**
 * @brief Verify the pflash integrity (signature)
 *
 * @param bootloader_start The start address of the pflash
 *
 * @note This function panics if the pflash is not valid
 */
bool verify_bootloader(const void *bootloader_start);

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
 * @param bootloader_start The start address of the pflash
 * @param bootloader_aes_key The AES key to decrypt the pflash
 *
 * @note This function panics if the pflash is not valid
 */
void decrypt_bootloader(void *bootloader_start,
                        const unsigned char *bootloader_aes_key);

#endif /* PREBOOT_H */
