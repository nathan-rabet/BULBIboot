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
BOOTLOADER_ELF=pikaboot.elf
BOOTLOADER_IMG=pikaboot.img
PFLASH_BIN=pflash.bin

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
# Sources
SRC_C = $(shell find src -name '*.c')
SRC_S = $(shell find src -name '*.S')

SRC_WOLFCRYPT = $(shell find modules/wolf/wolfcrypt/src -name '*.c')
OBJ_WOLFCRYPT = $(SRC_WOLFCRYPT:%.c=$(BUILD)/%.o)

SRC_CYCLONE = $(shell find modules/cyclone -name '*.c')
OBJ_CYCLONE = $(SRC_CYCLONE:%.c=$(BUILD)/%.o)

LIB_TOMCRYPT = $(BUILD)/modules/libtomcrypt/lib/libtomcrypt.a
LIB_TOMCRYPT_HEADERS = modules/libtomcrypt/src/headers

OBJS = $(SRC_C:%.c=$(BUILD)/%.o) $(SRC_S:%.S=$(BUILD)/%.o)

################################################################################
# Compilation options
CINCLUDE = -Iinclude -I$(LIB_TOMCRYPT_HEADERS)
CDEBUG = -g
CERROR = -W -Werror -Wall -Wextra -Werror
CSTD = -std=c99
COPTIONS = -ffreestanding -fno-stack-protector -fno-zero-initialized-in-bss
COPTIM = -O0

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

$(PFLASH_BIN): $(BUILD)/$(PFLASH_BIN)
	$(info $(PFLASH_BIN) generated successfully)
	
$(BUILD)/$(BOOTLOADER_ELF): $(OBJS) $(LIB_TOMCRYPT)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD)/$(BOOTLOADER_IMG): $(BUILD)/$(BOOTLOADER_ELF)
	$(CROSS_COMPILE)objcopy -O binary $< $@

$(BUILD)/$(PFLASH_BIN): $(BUILD)/$(BOOTLOADER_IMG) $(KERNEL_PATH)
	$(V)dd if=/dev/zero of=$@ bs=1M count=512
	$(V)dd if=$< of=$@ conv=notrunc bs=1M count=20
	$(V)dd if=$(KERNEL_PATH) of=$@ conv=notrunc bs=1M seek=50

.PHONY: boot
boot: $(BUILD)/$(PFLASH_BIN) $(INITRD_PATH)
	qemu-system-aarch64 \
	-machine virt \
	-nographic \
	-cpu cortex-a72 \
	-kernel $(BUILD)/$(PFLASH_BIN) \
	-initrd $(INITRD_PATH) \
	-serial pty \
	-m 2G \
	-smp 1 \
	-d in_asm \
	-D qemu.log \
	$(QEMU_ADDITIONAL_FLAGS)

.PHONY: boot_gdb
boot_gdb:
	$(MAKE) boot QEMU_ADDITIONAL_FLAGS="-gdb tcp::6666 -S"

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
# libtomcrypt
################################################################################
libtomcrypt: $(LIB_TOMCRYPT)
	$(info Libtomcrypt build finished !)

$(LIB_TOMCRYPT): modules/libtomcrypt
	$(MAKE) -C modules/libtomcrypt install \
	PREFIX=$(shell pwd)/$(BUILD)/modules/libtomcrypt \
	IGNORE_SPEED=1 \
	CFLAGS="-g"

################################################################################
# Wolfcrypt
################################################################################
wolfcrypt: CINCLUDE = -Imodules/wolf
wolfcrypt: COPTIONS = 
wolfcrypt: CERROR =
wolfcrypt: $(OBJ_WOLFCRYPT)
	$(info Wolfcrypt build finished !)

################################################################################
# Mbedtls
################################################################################
mbedtls: CINCLUDE = -Imodules/mbedtls/include
mbedtls: COPTIONS =
mbedtls: 
	$(MAKE) -C modules/mbedtls lib DESTDIR=$(shell pwd)/$(BUILD)/modules/mbedtls

################################################################################
# Cyclone
################################################################################
cyclone: CINCLUDE = -Imodules/cyclone -Imodules/cyclone/cyclone_crypto -Imodules/cyclone/common -Imodules/cyclone/config
cyclone: COPTIONS = -DGPL_LICENSE_TERMS_ACCEPTED -U__linux__
cyclone: CERROR =
cyclone: $(OBJ_CYCLONE)
	$(info Cyclone build finished !)

################################################################################
# Clean
################################################################################
PHONY: clean
clean:
	$(MAKE) -C modules/libtomcrypt clean PREFIX=$(shell pwd)/$(BUILD)/modules/libtomcrypt
	$(RM) -r $(BUILD)/modules/ \
	$(RM) -r $(BUILD)/src/ \
	$(BUILD)/$(BOOTLOADER_ELF) \
	$(BUILD)/$(BOOTLOADER_IMG) \
	$(BUILD)/$(PFLASH_BIN)
################################################################################
# Objects files
################################################################################
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
