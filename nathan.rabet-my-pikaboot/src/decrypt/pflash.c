#include "pflash.h"

#include "crypto.h"
#include "kassert.h"
#include "virt.h"

// Signature of bootloader (SHA512 + RSA)
static const unsigned char bootloader_bin_sig[] = {
#include "bulbiboot.img.sig.hex"
};

// SHA256 hash of AES key
static const unsigned char aes_key_hash[] = {
#include "bulbiboot.img.enc.key.hash.hex"
};

// Distinguished Encoding Rules (DER) ASN.1 RSA public key
static const unsigned char bootloader_pub_der_key[] = {
#include "bulbiboot.img.pub.der.hex"
};

void verify_pflash(void *pflash_start)
{
    unsigned char *bootloader_bin =
        (unsigned char *)pflash_start + BOOTLOADER_BIN_ADDR;
    size_t bootloader_bin_len = BOOTLOADER_BIN_LEN;
    unsigned char *bootloader_bin_hash =
        sha512(bootloader_bin, bootloader_bin_len);

    rsa_key key = { 0 };
    bool is_parsed = parse_rsa_der(bootloader_pub_der_key,
                                   sizeof(bootloader_pub_der_key), &key);
    kassertm(is_parsed, "Failed to parse RSA public key");

    bool is_verified =
        rsa_verify_sig(bootloader_bin_hash, SHA512_DIGEST_LEN,
                       bootloader_bin_sig, sizeof(bootloader_bin_sig), &key);
    kassertm(is_verified, "Failed to verify bootloader signature");
}

bool verify_bootloader_aes_key(const unsigned char *bootloader_aes_key)
{
    unsigned char *bootloader_aes_key_hash = sha256(bootloader_aes_key, 32);

    bool is_verified =
        memcmp(bootloader_aes_key_hash, aes_key_hash, SHA256_DIGEST_LEN) == 0;

    XFREE(bootloader_aes_key_hash);
    return is_verified;
}

void decrypt_pflash(void *pflash_start, const unsigned char *bootloader_aes_key)
{
    size_t bootloader_bin_len = BOOTLOADER_BIN_LEN;
    size_t bootloader_bin_addr = BOOTLOADER_BIN_ADDR;
    bool is_decrypted =
        aes256cbc_decrypt((unsigned char *)pflash_start + bootloader_bin_addr,
                          bootloader_bin_len, bootloader_aes_key);
    kassertm(is_decrypted, "Failed to decrypt bootloader");
}
