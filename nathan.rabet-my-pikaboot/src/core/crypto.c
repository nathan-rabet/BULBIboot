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
