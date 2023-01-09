#include "preboot.h"

#include "crypto.h"
#include "kassert.h"
#include "virt.h"

// Signature of bootloader (SHA256 + RSA)
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

bool verify_bootloader(const void *bootloader_start)
{
    rsa_key key = { 0 };
    kassertm(parse_rsa_der(bootloader_pub_der_key,
                           sizeof(bootloader_pub_der_key), &key),
             "Failed to parse RSA public key");

    bool is_verified =
        rsa_verify_sig(bootloader_start, ENCRYPTED_BOOTLOADER_IMG_LEN,
                       bootloader_bin_sig, sizeof(bootloader_bin_sig), &key);

    rsa_free(&key);
    return is_verified;
}

bool verify_bootloader_aes_key(const unsigned char *bootloader_aes_key)
{
    unsigned char *bootloader_aes_key_hash = sha256(bootloader_aes_key, 32);

    bool is_verified =
        memcmp(bootloader_aes_key_hash, aes_key_hash, SHA256_DIGEST_LEN) == 0;

    XFREE(bootloader_aes_key_hash);
    return is_verified;
}

void decrypt_bootloader(void *bootloader_start,
                        const unsigned char *bootloader_aes_key)
{
    bool is_decrypted =
        aes256cbc_decrypt((unsigned char *)bootloader_start, BOOTLOADER_IMG_LEN,
                          bootloader_aes_key);
    kassertm(is_decrypted, "Failed to decrypt bootloader");
}
