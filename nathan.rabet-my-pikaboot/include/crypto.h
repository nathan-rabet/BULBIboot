#ifndef CRYPTO_H
#define CRYPTO_H

extern const unsigned char pflash_bin_sig;

#define SHA512_DIGEST_LEN 64

#define AES256_KEY_LEN (256 >> 3)
#define AES256_IV_LEN (128 >> 3)

#include <stdbool.h>
#include <stddef.h>
#include <tomcrypt.h>

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

/**
 * @brief Verify the signature of a buffer using RSA
 *
 * @note This function uses the tomcrypt library
 *
 * @param buf The buffer to verify
 * @param len The length of the buffer
 * @param key The RSA key to use
 */
bool parse_rsa_der(const unsigned char *buf, size_t len, rsa_key *key);

/**
 * @brief Verify the signature of a buffer using RSA
 *
 * @note This function uses the tomcrypt library
 *
 * @param buf The buffer to verify
 * @param len The length of the buffer
 * @param sig The signature of the buffer
 * @param sig_len The length of the signature
 * @param key The RSA key to use
 */
bool rsa_verify_sig(const unsigned char *buf, size_t len,
                    const unsigned char *sig, size_t sig_len, rsa_key *key);

/**
 * @brief Decrypt a buffer using AES-256-CBC
 *
 * @note This function uses the tomcrypt library
 * @note The IV is assumed to be 0
 * @note The buffer is modified in place
 *
 * @param buf The buffer to decrypt
 * @param len The length of the buffer
 * @param key The key to use
 * @return true if the decryption was successful, false otherwise
 */
bool aes256cbc_decrypt(unsigned char *buf, size_t len,
                       const unsigned char *key);

#endif /* CRYPTO_H */
