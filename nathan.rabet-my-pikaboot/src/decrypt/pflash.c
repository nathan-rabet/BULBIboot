#include "pflash.h"

#include "crypto.h"
#include "kassert.h"
#include "virt.h"

// Signature of bootloader (SHA512 + RSA)
static const unsigned char bootloader_bin_sig[] = {
#include "bulbiboot.img.sig.hex"
};

// AES 256 CBC key (no salt)
static const unsigned char bootloader_aes_key[] = {
#include "bulbiboot.img.enc.key.hex"
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

void decrypt_pflash(void *pflash_start)
{
    size_t bootloader_bin_len = BOOTLOADER_BIN_LEN;
    size_t bootloader_bin_addr = BOOTLOADER_BIN_ADDR;
    bool is_decrypted =
        aes256cbc_decrypt((unsigned char *)pflash_start + bootloader_bin_addr,
                          bootloader_bin_len, bootloader_aes_key);
    kassertm(is_decrypted, "Failed to decrypt bootloader");
}
