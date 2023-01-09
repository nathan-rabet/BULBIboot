// Using tomcrypt
#include "crypto.h"

#include <tomcrypt.h>

#include "kassert.h"
#include "kstring.h"
#include "number.h"

void init_crypto(void)
{
    ltc_mp = ltm_desc;
    register_all_ciphers();
    register_all_hashes();
}

unsigned char *sha512(const unsigned char *buf, size_t len)
{
    unsigned char *hash = XMALLOC(SHA512_DIGEST_LEN);
    hash_state state = { 0 };
    sha512_init(&state);
    sha512_process(&state, buf, len);
    sha512_done(&state, hash);
    return hash;
}

char *sha512_hex(const unsigned char *buf, size_t len)
{
    unsigned char hash[SHA512_DIGEST_LEN];
    char *hex = XMALLOC(2 * SHA512_DIGEST_LEN + 1);
    hash_state state = { 0 };
    sha512_init(&state);
    sha512_process(&state, buf, len);
    sha512_done(&state, hash);
    for (int i = 0; i < SHA512_DIGEST_LEN; i++)
    {
        char *chars = aligned_numtoi64(itoa64hex_no0x((char)hash[i]), 2);

        hex[i * 2] = chars[0];
        hex[i * 2 + 1] = chars[1];
    }
    hex[2 * SHA512_DIGEST_LEN] = '\0';
    return hex;
}

unsigned char *sha256(const unsigned char *buf, size_t len)
{
    unsigned char *hash = XMALLOC(SHA256_DIGEST_LEN);
    hash_state state = { 0 };
    sha256_init(&state);
    sha256_process(&state, buf, len);
    sha256_done(&state, hash);
    return hash;
}

char *sha256_hex(const unsigned char *buf, size_t len)
{
    unsigned char hash[SHA256_DIGEST_LEN];
    char *hex = XMALLOC(2 * SHA256_DIGEST_LEN + 1);
    hash_state state = { 0 };
    sha256_init(&state);
    sha256_process(&state, buf, len);
    sha256_done(&state, hash);
    for (int i = 0; i < SHA256_DIGEST_LEN; i++)
    {
        char *chars = aligned_numtoi64(itoa64hex_no0x((char)hash[i]), 2);

        hex[i * 2] = chars[0];
        hex[i * 2 + 1] = chars[1];
    }
    hex[2 * SHA256_DIGEST_LEN] = '\0';
    return hex;
}

// Parse PEM encoded RSA key
bool parse_rsa_der(const unsigned char *buf, size_t len, rsa_key *key)
{
    int ret = rsa_import(buf, len, key);
    return ret == CRYPT_OK;
}

// Verify RSA signature
bool rsa_verify_sig(const unsigned char *buf, size_t len,
                    const unsigned char *sig, size_t sig_len, rsa_key *key)
{
    unsigned char hash[SHA256_DIGEST_LEN];
    hash_state state = { 0 };
    kassertm(sha256_init(&state) == CRYPT_OK, "SHA256 init failed");
    kassertm(sha256_process(&state, buf, len) == CRYPT_OK,
             "SHA256 process failed");
    kassertm(sha256_done(&state, hash) == CRYPT_OK, "SHA256 done failed");

#ifdef DEBUG
    char *hex = sha256_hex(buf, len);
#    include "console.h"
    kputs("SHA256: ");
    kputs(hex);
    kputs(" ");
#endif

    int hash_idx = find_hash("sha256");
    int stat = 0;
    kassertm(rsa_verify_hash_ex(sig, sig_len, hash, SHA256_DIGEST_LEN,
                                LTC_PKCS_1_V1_5, hash_idx, 0, &stat, key)
                 == CRYPT_OK,
             "Signature verification procedure failed");
    return stat == 1;
}

// AES-256-CBC decryption
bool aes256cbc_decrypt(unsigned char *buf, size_t len, const unsigned char *key)
{
    unsigned char iv[AES256_IV_LEN] = { 0 };
    int cipher;
    symmetric_CBC cbc;

    // Register AES cipher
    cipher = register_cipher(&aes_desc);
    if (cipher == -1)
        return false;

    // Start CBC mode
    int ret = cbc_start(cipher, iv, key, AES256_KEY_LEN, 0, &cbc);
    if (ret != CRYPT_OK)
        return false;

    // Align length to block size
    len = (len + AES256_KEY_LEN - 1) & ~(AES256_KEY_LEN - 1);

    // Decrypt
    return cbc_decrypt(buf, buf, len, &cbc) == CRYPT_OK;
}
