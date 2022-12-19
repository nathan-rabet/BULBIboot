// Using tomcrypt
#include "crypto.h"

#include <tomcrypt.h>

#include "kstring.h"
#include "number.h"

unsigned char *sha512(unsigned char *buf, size_t len)
{
    unsigned char *hash = XMALLOC(SHA512_DIGEST_SIZE);
    hash_state state = { 0 };
    sha512_init(&state);
    sha512_process(&state, buf, len);
    sha512_done(&state, hash);
    return hash;
}

char *sha512_hex(unsigned char *buf, size_t len)
{
    unsigned char hash[SHA512_DIGEST_SIZE];
    char *hex = XMALLOC(2 * SHA512_DIGEST_SIZE + 1);
    hash_state state = { 0 };
    sha512_init(&state);
    sha512_process(&state, buf, len);
    sha512_done(&state, hash);
    for (int i = 0; i < SHA512_DIGEST_SIZE; i++)
    {
        char *chars = aligned_numtoi64(itoa64hex_no0x((char)hash[i]), 2);

        hex[i * 2] = chars[0];
        hex[i * 2 + 1] = chars[1];
    }
    hex[2 * SHA512_DIGEST_SIZE] = '\0';
    return hex;
}

// Parse PEM encoded RSA key
bool parse_rsa_der(unsigned char *buf, size_t len, rsa_key *key)
{
    int ret = rsa_import(buf, len, key);
    return ret == CRYPT_OK;
}

// Verify RSA signature
bool rsa_verify(unsigned char *buf, size_t len, unsigned char *sig,
                size_t sig_len, rsa_key *key)
{
    unsigned char hash[SHA512_DIGEST_SIZE];
    hash_state state = { 0 };
    sha512_init(&state);
    sha512_process(&state, buf, len);
    sha512_done(&state, hash);
    int stat = 0;
    return rsa_verify_hash_ex(sig, sig_len, hash, SHA512_DIGEST_SIZE,
                              LTC_PKCS_1_OAEP, 0, 0, &stat, key)
        == CRYPT_OK;
}

// AES-256-CBC decryption
bool aes256cbc_decrypt(unsigned char *buf, size_t len, unsigned char *key)
{
    unsigned char iv[AES256_IV_LENGTH] = { 0 };
    int cipher;
    symmetric_CBC cbc;

    // Register AES cipher
    cipher = register_cipher(&aes_desc);
    if (cipher == -1)
        return false;

    // Start CBC mode
    if (cbc_start(cipher, iv, key, AES256_KEY_LENGTH, 0, &cbc) != CRYPT_OK)
        return false;

    // Decrypt
    return cbc_decrypt(buf, buf, len, &cbc) == CRYPT_OK;
}
