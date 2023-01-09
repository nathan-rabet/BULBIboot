NCORE?=$(shell nproc)
MAKE=make -j$(NCORE)

###################################################################################################
#       ___           ___                                   ___           ___           ___       #
#      /\  \         /\  \                                 /\  \         /\  \         /\__\      #
#     /::\  \       /::\  \       ___         ___         /::\  \        \:\  \       /:/ _/_     #
#    /:/\:\  \     /:/\:\__\     /\__\       /\__\       /:/\:\  \        \:\  \     /:/ /\  \    #
#   /:/  \:\  \   /:/ /:/  /    /:/  /      /:/__/      /:/  \:\  \   _____\:\  \   /:/ /::\  \   #
#  /:/__/ \:\__\ /:/_/:/  /    /:/__/      /::\  \     /:/__/ \:\__\ /::::::::\__\ /:/_/:/\:\__\  #
#  \:\  \ /:/  / \:\/:/  /    /::\  \      \/\:\  \__  \:\  \ /:/  / \:\~~\~~\/__/ \:\/:/ /:/  /  #
#   \:\  /:/  /   \::/__/    /:/\:\  \      ~~\:\/\__\  \:\  /:/  /   \:\  \        \::/ /:/  /   #
#    \:\/:/  /     \:\  \    \/__\:\  \        \::/  /   \:\/:/  /     \:\  \        \/_/:/  /    #
#     \::/  /       \:\__\        \:\__\       /:/  /     \::/  /       \:\__\         /:/  /     #
#      \/__/         \/__/         \/__/       \/__/       \/__/         \/__/         \/__/      #
###################################################################################################
# Build options
BUILD=build

# Cross-compliation options
ARCH?=arm64
CROSS_COMPILE?=aarch64-linux-gnu-
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AS=$(CROSS_COMPILE)as

################################################################################
# Bootloader options
BOOTLOADER_NAME=bulbiboot

BOOTLOADER_ELF=$(BOOTLOADER_NAME).elf
BOOTLOADER_IMG=$(BOOTLOADER_NAME).img


ENCRYPTED_BOOTLOADER_IMG=$(BOOTLOADER_IMG).enc
ENCRYPTED_BOOTLOADER_IMG_KEY=$(ENCRYPTED_BOOTLOADER_IMG).key
ENCRYPTED_BOOTLOADER_IMG_KEY_TXT=$(ENCRYPTED_BOOTLOADER_IMG_KEY).txt
ENCRYPTED_BOOTLOADER_IMG_KEY_HASH=$(ENCRYPTED_BOOTLOADER_IMG_KEY).hash
ENCRYPTED_BOOTLOADER_IMG_KEY_HASH_HEX=$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH).hex

BOOTLOADER_PEM_PRIVATE=$(BOOTLOADER_IMG).pem
BOOTLOADER_DER_PUBLIC=$(BOOTLOADER_IMG).pub.der
BOOTLOADER_DER_PUBLIC_HEX=$(BOOTLOADER_DER_PUBLIC).hex

BOOTLOADER_SIG=$(BOOTLOADER_IMG).sig
BOOTLOADER_SIG_HEX=$(BOOTLOADER_SIG).hex

################################################################################
# Prebootloader options
DECRYPTOR_ELF=decryptor_$(BOOTLOADER_ELF)
DECRYPTOR_IMG=decryptor_$(BOOTLOADER_IMG)

################################################################################
# Pflash options
PFLASH_BIN=pflash.bin
ENCRYPTED_PFLASH_BIN=$(PFLASH_BIN).enc

# Length of the pflash
PFLASH_LEN_MB=512

# Offsets in the pflash
DECRYPTOR_BIN_OFFSET_MB=0
BOOTLOADER_BIN_OFFSET_MB=30
KERNEL_BIN_OFFSET_MB=50

################################################################################
# Thirdparty options
KERNEL=thirdparty/$(ARCH)/Image
INITRD=thirdparty/$(ARCH)/initramfs.cpio.gz

KERNEL_PEM_PRIVATE=$(KERNEL).pem
KERNEL_DER_PUBLIC=$(KERNEL).pub.der
KERNEL_DER_PUBLIC_HEX=$(KERNEL_DER_PUBLIC).hex

KERNEL_SIG=$(KERNEL).sig
KERNEL_SIG_HEX=$(KERNEL_SIG).hex

################################################################################
# Linker options
LDFLAGS:= -nostdlib -T link.ld

################################################################################
# Decryptor source files
SRC_DECRYPT_C = $(shell find src -name '*.c' -a ! -path 'src/boot/*')
SRC_DECRYPT_S = $(shell find src -name '*.S' -a ! -path 'src/boot/*')
OBJS_DECRYPT = $(SRC_DECRYPT_C:%.c=$(BUILD)/%.o) $(SRC_DECRYPT_S:%.S=$(BUILD)/%.o)

# Core source files
SRC_CORE_C = $(shell find src -name '*.c' -a ! -path 'src/preboot/*')
SRC_CORE_S = $(shell find src -name '*.S' -a ! -path 'src/preboot/*')
OBJS_CORE = $(SRC_CORE_C:%.c=$(BUILD)/%.o) $(SRC_CORE_S:%.S=$(BUILD)/%.o)

################################################################################
# Libraries
LIB_TOMCRYPT = $(BUILD)/lib/libtomcrypt/lib/libtomcrypt.a
LIB_TOMCRYPT_HEADERS = lib/libtomcrypt/src/headers

LIB_TOMMATH = $(BUILD)/lib/libtommath/lib/libtommath.a
LIB_TOMMATH_HEADERS = lib/libtommath

# LibGCC (Needed for __udivti3 in libtommath)
LIB_GCC=/lib/gcc-cross/aarch64-linux-gnu/12/libgcc.a

################################################################################
# Compilator options
CINCLUDE = -Iinclude -I$(LIB_TOMCRYPT_HEADERS) -I$(BUILD)
CDEBUG = -g
CERROR = -W -Werror -Wall -Wextra -Werror
CSTD = -std=c99
COPTIONS = -ffreestanding -fno-stack-protector -fno-zero-initialized-in-bss
COPTIONS += -D BOOTLOADER_BIN_OFFSET=$(shell echo $$(( $(BOOTLOADER_BIN_OFFSET_MB) * 1024 * 1024 )))
COPTIONS += -D KERNEL_BIN_OFFSET=$(shell echo $$(( $(KERNEL_BIN_OFFSET_MB) * 1024 * 1024 )))
COPTIM = -O3

################################################################################
# Machine options
BOOT_IMG?=$(BUILD)/$(ENCRYPTED_PFLASH_BIN)
RAM_SIZE_GB=2
RAM_SIZE_BYTES=$(shell echo $$(( $(RAM_SIZE_GB) * 1024 * 1024 * 1024 )))
