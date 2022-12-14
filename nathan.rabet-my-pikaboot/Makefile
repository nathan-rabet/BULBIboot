NCORE?=$(shell nproc)
BUILD=build

################################################################################
# BOOTLOADER
################################################################################

CROSS_COMPILE?=aarch64-linux-gnu-
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AS=$(CROSS_COMPILE)as

BOOTLOADER_ELF=pikaboot.elf
BOOTLOADER_IMG=pikaboot.img
PFLASH_BIN=pflash.bin

KERNEL_PATH=$(BUILD)/thirdparty/Image
INITRD_PATH=$(BUILD)/thirdparty/initramfs.cpio.gz

RAM_SIZE_GB?=2
BOOTLOADER_SIZE_MB?=$(shell du -m $(BUILD)/$(BOOTLOADER_IMG) | cut -f1)

KERMIT_FLAGS= -DNODEBUG

CFLAGS:=-Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-zero-initialized-in-bss -O0 -g -c
CFLAGS += -Iinclude -I./modules/kermit/core
CFLAGS += -DRAM_SIZE_GB=$(RAM_SIZE_GB) -DKERNEL_SIZE_MB=$(KERNEL_SIZE_MB) -DBOOTLOADER_SIZE_MB=$(BOOTLOADER_SIZE_MB)
CFLAGS += -DNODEBUG
LDFLAGS:=-nostdlib -T link.ld

SRC_C=$(shell find src -name '*.c')
SRC_S=$(shell find src -name '*.S')

OBJS=$(SRC_C:%.c=$(BUILD)/%.o) $(SRC_S:%.S=$(BUILD)/%.o)

all: boot
	

$(BUILD)/$(BOOTLOADER_ELF): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD)/$(BOOTLOADER_IMG): $(BUILD)/$(BOOTLOADER_ELF)
	$(CROSS_COMPILE)objcopy -O binary $< $@

$(BUILD)/$(PFLASH_BIN): $(BUILD)/$(BOOTLOADER_IMG) $(KERNEL_PATH)
	$(V)dd if=/dev/zero of=$@ bs=1M count=512
	$(V)dd if=$< of=$@ conv=notrunc bs=1M count=20
	$(V)dd if=$(KERNEL_PATH) of=$@ conv=notrunc bs=1M seek=50


$(PFLASH_BIN): $(BUILD)/$(PFLASH_BIN)

.PHONY: boot
boot: $(BUILD)/$(PFLASH_BIN) $(INITRD_PATH)
	qemu-system-aarch64 \
	-machine virt \
	-nographic \
	-cpu cortex-a72 \
	-kernel $(BUILD)/$(PFLASH_BIN) \
	-initrd $(INITRD_PATH) \
	-serial pty \
	-m $(RAM_SIZE_GB)G \
	-smp 1 \
	-d in_asm \
	-D qemu.log \
	$(QEMU_ADDITIONAL_FLAGS)

.PHONY: boot_gdb
boot_gdb:
	$(MAKE) boot QEMU_ADDITIONAL_FLAGS="-gdb tcp::6666 -S"


# .PHONY: boot_cheat
# boot_cheat: $(KERNEL_PATH) $(INITRD_PATH)
# 	qemu-system-aarch64 \
# 	-machine virt \
# 	-cpu cortex-a72 \
# 	-kernel $(KERNEL_PATH) \
# 	-initrd $(INITRD_PATH) \
# 	-serial mon:stdio \
# 	-m $(RAM_SIZE_GB)G \
# 	-smp 4

# object files
$(BUILD)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.S
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

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

$(BUILD)/linux-5.19.17/arch/arm64/boot/Image: $(BUILD)/linux-5.19.17/.config
	cd $(BUILD)/linux-5.19.17/ && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image -j $(NCORE) && cd ..

$(BUILD)/thirdparty:
	mkdir -p $(BUILD)/thirdparty

$(KERNEL): $(BUILD)/linux-5.19.17/arch/arm64/boot/Image thirdparty
	cp $< $@

$(BUILD)/busybox-1.35.0/.config: $(BUILD)/busybox-1.35.0
	cd $(BUILD)/busybox-1.35.0/ && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
	cp cfg/busybox_cfg $@

$(BUILD)/busybox-1.35.0/_install: $(BUILD)/busybox-1.35.0/.config
	cd $(BUILD)/busybox-1.35.0 && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- install -j $(NCORE)

$(BUILD)/busybox-1.35.0/initramfs: $(BUILD)/busybox-1.35.0/_install
	mkdir -pv $@
	cd $@ && for i in bin sbin etc proc sys usr/bin usr/sbin; do mkdir -pv $$i; done && cp -a ../_install/* .

$(BUILD)/busybox-1.35.0/initramfs/init: $(BUILD)/busybox-1.35.0/initramfs
	cd $(BUILD)/busybox-1.35.0 && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- install -j $(NCORE)
	cp cfg/busybox_init $@
	chmod +x $@

$(BUILD)/busybox-1.35.0/initramfs.cpio.gz: $(BUILD)/busybox-1.35.0/initramfs/init
	cd $(BUILD)/busybox-1.35.0/initramfs && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

$(INITRD_PATH): $(BUILD)/busybox-1.35.0/initramfs.cpio.gz $(BUILD)/thirdparty
	cp $< $@

################################################################################
# Clean
################################################################################

PHONY: clean
clean:
	$(RM) $(shell find $(BUILD)/src -name '*.o') \
	$(shell find $(BUILD)/modules -name '*.o') \
	$(BUILD)/$(BOOTLOADER_ELF) \
	$(BUILD)/$(BOOTLOADER_IMG) \

################################################################################
# Dependences
################################################################################
.PHONY: dependences
dependences:
		sudo apt install -y gcc-aarch64-linux-gnu
		sudo apt install -y bison
		sudo apt install qemu-system-arm
