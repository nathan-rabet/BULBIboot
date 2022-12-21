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

DECRYPTOR_ELF=decryptor_$(BOOTLOADER_ELF)
DECRYPTOR_IMG=decryptor_$(BOOTLOADER_IMG)

DECRYPTOR_BIN_OFFSET_MB=0
BOOTLOADER_BIN_OFFSET_MB=10
KERNEL_BIN_OFFSET_MB=50

PFLASH_BIN=pflash.bin
ENCRYPTED_PFLASH_BIN=$(PFLASH_BIN).enc

BOOT_IMG?=$(BUILD)/$(ENCRYPTED_PFLASH_BIN)

BOOTLOADER_PEM_PRIVATE=$(BOOTLOADER_IMG).pem
BOOTLOADER_DER_PUBLIC=$(BOOTLOADER_IMG).pub.der
BOOTLOADER_DER_PUBLIC_HEX=$(BOOTLOADER_DER_PUBLIC).hex

BOOTLOADER_SIG=$(BOOTLOADER_IMG).sig
BOOTLOADER_SIG_HEX=$(BOOTLOADER_SIG).hex

ENCRYPTED_BOOTLOADER_IMG=$(BOOTLOADER_IMG).enc
ENCRYPTED_BOOTLOADER_IMG_KEY=$(ENCRYPTED_BOOTLOADER_IMG).key
ENCRYPTED_BOOTLOADER_IMG_KEY_HEX=$(ENCRYPTED_BOOTLOADER_IMG_KEY).hex

################################################################################
# Thirdparty options
KERNEL_PATH=$(BUILD)/thirdparty/$(ARCH)/Image
INITRD_PATH=$(BUILD)/thirdparty/$(ARCH)/initramfs.cpio.gz

################################################################################
# Build options
BUILD=build

################################################################################
# Linker options
LDFLAGS:= -nostdlib -T link.ld

################################################################################
# Decryptor source files
SRC_DECRYPT_C = $(shell find src -name '*.c' -a ! -path 'src/core/*')
SRC_DECRYPT_S = $(shell find src -name '*.S' -a ! -path 'src/core/*')

OBJS_DECRYPT = $(SRC_DECRYPT_C:%.c=$(BUILD)/%.o) $(SRC_DECRYPT_S:%.S=$(BUILD)/%.o)

# Core source files
SRC_CORE_C = $(shell find src -name '*.c' -a ! -path 'src/decrypt/*')
SRC_CORE_S = $(shell find src -name '*.S' -a ! -path 'src/decrypt/*')

OBJS_CORE = $(SRC_CORE_C:%.c=$(BUILD)/%.o) $(SRC_CORE_S:%.S=$(BUILD)/%.o)

################################################################################
# Libraries
LIB_TOMCRYPT = $(BUILD)/modules/libtomcrypt/lib/libtomcrypt.a
LIB_TOMCRYPT_HEADERS = modules/libtomcrypt/src/headers

LIB_TOMMATH = $(BUILD)/modules/libtommath/lib/libtommath.a
LIB_TOMMATH_HEADERS = modules/libtommath

# Needed for __udivti3 in libtommath
LIB_GCC=$(shell locate libgcc.a | grep "aarch64" | grep "linux-gnu" | head -n 1)

################################################################################
# Compilator options
CINCLUDE = -I$(BUILD) -Iinclude -I$(LIB_TOMCRYPT_HEADERS)
CDEBUG = -g
CERROR = -W -Werror -Wall -Wextra -Werror
CSTD = -std=c99
COPTIONS = -ffreestanding -fno-stack-protector -fno-zero-initialized-in-bss
COPTIONS += -DBOOTLOADER_BIN_OFFSET_MB=$(BOOTLOADER_BIN_OFFSET_MB) -DKERNEL_BIN_OFFSET_MB=$(KERNEL_BIN_OFFSET_MB)
COPTIM = -O3

################################################################################
# Machine options
RAM_SIZE_GB=2
RAM_SIZE_BYTES=$(shell echo $$(( $(RAM_SIZE_GB) * 1024 * 1024 * 1024 )))

###########################################################################
#       ___           ___                         ___           ___       #
#      /\  \         /\  \                       /\__\         /\__\      #
#     /::\  \        \:\  \                     /:/ _/_       /:/ _/_     #
#    /:/\:\__\        \:\  \                   /:/ /\__\     /:/ /\  \    #
#   /:/ /:/  /    ___  \:\  \   ___     ___   /:/ /:/ _/_   /:/ /::\  \   #
#  /:/_/:/__/___ /\  \  \:\__\ /\  \   /\__\ /:/_/:/ /\__\ /:/_/:/\:\__\  #
#  \:\/:::::/  / \:\  \ /:/  / \:\  \ /:/  / \:\/:/ /:/  / \:\/:/ /:/  /  #
#   \::/~~/~~~~   \:\  /:/  /   \:\  /:/  /   \::/_/:/  /   \::/ /:/  /   #
#    \:\~~\        \:\/:/  /     \:\/:/  /     \:\/:/  /     \/_/:/  /    #
#     \:\__\        \::/  /       \::/  /       \::/  /        /:/  /     #
#      \/__/         \/__/         \/__/         \/__/         \/__/      #
###########################################################################

.PHONY: images
images: $(BUILD)/$(DECRYPTOR_IMG) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG)
	$(info Images generated successfully)

.PHONY: boot
boot: $(BOOT_IMG) $(INITRD_PATH)
	qemu-system-aarch64 \
	-machine virt,virtualization=on,secure=on \
	-nographic \
	-cpu cortex-a72 \
	-kernel $(BOOT_IMG) \
	-initrd $(INITRD_PATH) \
	-serial mon:stdio \
	-m 2G \
	-smp 1 \
	-d in_asm \
	-D qemu.log \
	$(QEMU_ADDITIONAL_FLAGS)

.PHONY: boot_gdb
boot_gdb: COPTIONS += -DDEBUG
boot_gdb: QEMU_ADDITIONAL_FLAGS=-gdb tcp::6666 -S
boot_gdb: boot

.PHONY: $(PFLASH_BIN)
$(PFLASH_BIN): $(BUILD)/$(PFLASH_BIN)
	$(info $(PFLASH_BIN) generated successfully)

.PHONY: $(ENCRYPTED_PFLASH_BIN)
$(ENCRYPTED_PFLASH_BIN): $(BUILD)/$(ENCRYPTED_PFLASH_BIN)
	$(info $(ENCRYPTED_PFLASH_BIN) generated successfully)

$(BUILD)/$(BOOTLOADER_ELF): $(OBJS_CORE) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD)/$(BOOTLOADER_IMG): $(BUILD)/$(BOOTLOADER_ELF)
	$(CROSS_COMPILE)objcopy -O binary $< $@

$(BUILD)/$(PFLASH_BIN): $(BUILD)/$(BOOTLOADER_IMG) $(KERNEL_PATH)
	$(V)dd if=/dev/zero of=$@ bs=1M count=512 seek=$(BOOTLOADER_BIN_OFFSET_MB)
	$(V)dd if=$(BUILD)/$(BOOTLOADER_IMG) of=$@ conv=notrunc bs=1M count=10
	$(V)dd if=$(KERNEL_PATH) of=$@ conv=notrunc bs=1M seek=$(KERNEL_BIN_OFFSET_MB)

$(BUILD)/$(ENCRYPTED_PFLASH_BIN): $(BUILD)/$(DECRYPTOR_IMG) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) $(KERNEL_PATH)
	$(V)dd if=/dev/zero of=$@ bs=1M count=512 seek=$(DECRYPTOR_BIN_OFFSET_MB)
	$(V)dd if=$(BUILD)/$(DECRYPTOR_IMG) of=$@ conv=notrunc bs=1M count=$(BOOTLOADER_BIN_OFFSET_MB)
	$(V)dd if=$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) of=$@ conv=notrunc bs=1M seek=$(BOOTLOADER_BIN_OFFSET_MB) count=10
	$(V)dd if=$(KERNEL_PATH) of=$@ conv=notrunc bs=1M seek=$(KERNEL_BIN_OFFSET_MB)

################################################################################
# Thirdparties
################################################################################
.PHONY: thirdparties
thirdparties: $(INITRD_PATH) $(KERNEL_PATH)
	$(info Thirdparty builds finished !)

$(BUILD)/busybox-1.35.0:
	curl -LO https://busybox.net/downloads/busybox-1.35.0.tar.bz2 --output $(BUILD)/busybox-1.35.0.tar.bz2
	tar jxvf $(BUILD)/busybox-1.35.0.tar.bz2 -C $(BUILD)
	cp cfg/busybox_cfg $(BUILD)/busybox-1.35.0/.config

$(BUILD)/linux-5.19.17:
	wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.19.17.tar.xz --output-document=$(BUILD)/linux-5.19.17.tar.xz
	tar -Jxvf $(BUILD)/linux-5.19.17.tar.xz

$(BUILD)/linux-5.19.17/.config: $(BUILD)/linux-5.19.17
	cp cfg/linux_cfg $@

$(BUILD)/linux-5.19.17/arch/$(ARCH)/boot/Image: $(BUILD)/linux-5.19.17/.config
	cd $(BUILD)/linux-5.19.17/ && make ARCH=$(ARCH) CROSS_COMPILE=aarch64-linux-gnu- Image -j $(NCORE) && cd ..

$(BUILD)/thirdparty/$(ARCH):
	mkdir -p $(BUILD)/thirdparty
	mkdir -p $@

$(KERNEL_PATH): $(BUILD)/linux-5.19.17/arch/$(ARCH)/boot/Image $(BUILD)/thirdparty/$(ARCH)
	cp $< $@

$(BUILD)/busybox-1.35.0/.config: $(BUILD)/busybox-1.35.0
	cd $(BUILD)/busybox-1.35.0/ && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) defconfig
	cp cfg/busybox_cfg $@

$(BUILD)/busybox-1.35.0/_install: $(BUILD)/busybox-1.35.0/.config
	cd $(BUILD)/busybox-1.35.0 && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) install

$(BUILD)/busybox-1.35.0/initramfs: $(BUILD)/busybox-1.35.0/_install
	mkdir -pv $@
	cd $@ && for i in bin sbin etc proc sys usr/bin usr/sbin; do mkdir -pv $$i; done && cp -a ../_install/* .

$(BUILD)/busybox-1.35.0/initramfs/init: $(BUILD)/busybox-1.35.0/initramfs
	cd $(BUILD)/busybox-1.35.0 && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) install
	cp cfg/busybox_init $@
	chmod +x $@

$(BUILD)/busybox-1.35.0/initramfs.cpio.gz: $(BUILD)/busybox-1.35.0/initramfs/init
	cd $(BUILD)/busybox-1.35.0/initramfs && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

$(INITRD_PATH): $(BUILD)/busybox-1.35.0/initramfs.cpio.gz $(BUILD)/thirdparty/$(ARCH)
	cp $< $@

################################################################################
# Crypto
################################################################################
.PHONY: crypto
crypto: $(BUILD)/$(BOOTLADER_DER_KEY) $(BUILD)/$(BOOTLOADER_SIG) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY)
	$(info Bootloader public DER, signature and encrypted bootloader image key generated !)

# Signature
$(BUILD)/$(BOOTLOADER_DER_PUBLIC): $(BUILD)/$(BOOTLOADER_PEM_PRIVATE)
	openssl rsa -in $< -pubout -outform DER -out $@

$(BUILD)/$(BOOTLOADER_PEM_PRIVATE):
	openssl genrsa -out $@ 2048

$(BUILD)/$(BOOTLOADER_SIG_HEX): $(BUILD)/$(BOOTLOADER_SIG)
	xxd -p -c 256 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(BOOTLOADER_DER_PUBLIC_HEX): $(BUILD)/$(BOOTLOADER_DER_PUBLIC)
	xxd -p -c 256 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(BOOTLOADER_SIG): $(BUILD)/$(BOOTLOADER_PEM_PRIVATE) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG)
	openssl dgst -sha256 -sign $< -out $@ $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG)

# Encryption
$(BUILD)/$(DECRYPTOR_ELF): $(BUILD)/$(BOOTLOADER_DER_PUBLIC_HEX) $(BUILD)/$(BOOTLOADER_SIG_HEX) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HEX) $(OBJS_DECRYPT) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)
	$(LD) $(LDFLAGS) -o $@ $(OBJS_DECRYPT) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)

$(BUILD)/$(DECRYPTOR_IMG):
$(BUILD)/$(DECRYPTOR_IMG): $(BUILD)/$(DECRYPTOR_ELF)
	$(CROSS_COMPILE)objcopy -O binary $< $@

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY):
	openssl rand -out $@ 32

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HEX): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY)
	xxd -p -c 256 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY) $(BUILD)/$(BOOTLOADER_IMG)
	openssl enc -aes-256-cbc \
	-in $(BUILD)/$(BOOTLOADER_IMG) \
	-out $@ \
	-K $(shell xxd -p -c 256 $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY) | sed 's/\(..\)/\1/g') \
	-iv 00000000000000000000000000000000 \

.PHONY: cleancrypto
cleancrypto:
	$(RM) $(BUILD)/$(BOOTLOADER_DER_PUBLIC) \
	$(BUILD)/$(BOOTLOADER_PEM_PRIVATE) \
	$(BUILD)/$(BOOTLOADER_SIG_HEX) \
	$(BUILD)/$(BOOTLOADER_SIG) \
	$(BUILD)/$(DECRYPTOR_ELF) \
	$(BUILD)/$(DECRYPTOR_IMG) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HEX) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) \
	$(BUILD)/$(BOOTLOADER_DER_PUBLIC_HEX) \
	$(BUILD)/$(ENCRYPTED_PFLASH_BIN)

################################################################################
# libtommath
################################################################################
.PHONY: libtommath
libtommath: $(LIB_TOMMATH)
	$(info Libtommath build finished !)

$(LIB_TOMMATH): modules/libtommath
	$(MAKE) -C modules/libtommath install \
	PREFIX=$(shell pwd)/$(BUILD)/modules/libtommath \
	IGNORE_SPEED=1 \
	CFLAGS="-g -DARGTYPE=4 -DMP_NO_DEV_URANDOM -U__linux__"

################################################################################
# libtomcrypt
################################################################################
.PHONY: libtomcrypt
libtomcrypt: $(LIB_TOMCRYPT)
	$(info Libtomcrypt build finished !)

$(LIB_TOMCRYPT): modules/libtomcrypt $(LIB_TOMMATH)
	$(MAKE) -C modules/libtomcrypt install \
	PREFIX=$(shell pwd)/$(BUILD)/modules/libtomcrypt \
	IGNORE_SPEED=1 \
	CFLAGS="-g -DUSE_LTM -DARGTYPE=4 -I$(shell pwd)/$(LIB_TOMMATH_HEADERS)"
	EXTRALIBS=$(LIB_TOMMATH)

################################################################################
# Clean
################################################################################
.PHONY: clean
clean: cleancrypto
	$(RM) -r $(BUILD)/src/ \
	$(BUILD)/$(BOOTLOADER_ELF) \
	$(BUILD)/$(BOOTLOADER_IMG) \
	$(BUILD)/$(PFLASH_BIN)

.PHONY: libclean
libclean:
	$(MAKE) -C modules/libtomcrypt clean PREFIX=$(shell pwd)/$(BUILD)/modules/libtomcrypt
	$(MAKE) -C modules/libtommath clean PREFIX=$(shell pwd)/$(BUILD)/modules/libtommath
	$(RM) -r $(BUILD)/modules/

.PHONY: allclean
allclean: clean libclean
	$(info All clean finished !)

################################################################################
# Objects files
################################################################################
$(BUILD)/%.o: COPTIONS += -DBOOTLOADER_BIN_LEN=$(shell wc -c $(BUILD)/$(BOOTLOADER_IMG) | cut -d' ' -f1)
$(BUILD)/%.o: COPTIONS += -DBOOTLOADER_CRC=$(shell crc32 $(BUILD)/$(BOOTLOADER_IMG) | sed 's/^\(.*\)$$/0x\1/')
$(BUILD)/%.o: COPTIONS += -DKERNEL_BIN_LEN=$(shell wc -c $(KERNEL_PATH) | cut -d' ' -f1)
$(BUILD)/%.o: COPTIONS += -DKERNEL_CRC=$(shell crc32 $(KERNEL_PATH) | sed 's/^\(.*\)$$/0x\1/')
$(BUILD)/%.o: COPTIONS += -DRAM_SIZE=$(RAM_SIZE_BYTES)
$(BUILD)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(COPTIONS) $(CSTD) $(CINCLUDE) $(CDEBUG) $(CERROR) $(COPTIM) -c $< -o $@

$(BUILD)/%.o: %.S
	mkdir -p $(dir $@)
	$(CC) $(COPTIONS) $(CSTD) $(CINCLUDE) $(CDEBUG) $(CERROR) $(COPTIM) -c $< -o $@

################################################################################
# Dependences
################################################################################
.PHONY: dependences
dependences:
		sudo apt install -y gcc-aarch64-linux-gnu
		sudo apt install -y bison
		sudo apt install qemu-system-arm
