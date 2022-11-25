NCORE?=$(shell nproc)
BUILD = build

################################################################################
# BOOTLOADER
################################################################################

CROSS_COMPILE?=aarch64-linux-gnu-
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AS=$(CROSS_COMPILE)as

BOOTLOADER=pikaboot

CFLAGS:=-Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-zero-initialized-in-bss -O0 -g -c -Iinclude
LDFLAGS:=-nostdlib -T link.ld

SRC_C = $(shell find src -name '*.c')
SRC_S = $(shell find src -name '*.S')

OBJS = $(SRC_C:%.c=$(BUILD)/%.o) $(SRC_S:%.S=$(BUILD)/%.o)

$(BOOTLOADER): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

.PHONY: boot
boot: $(BOOTLOADER) $(BUILD)/thirdparty/initramfs.cpio.gz
	qemu-system-aarch64 \
	-machine virt \
	-cpu cortex-a72 \
	-kernel $(BOOTLOADER) \
	-initrd thirdparty/initramfs.cpio.gz \
	-serial mon:stdio \
	-m 2G \
	-monitor telnet:127.0.0.1:55555,server,nowait;\
	-smp 4

.PHONY: boot_cheat
boot_cheat: $(BUILD)/thirdparty/Image $(BUILD)/thirdparty/initramfs.cpio.gz
	qemu-system-aarch64 \
	-machine virt \
	-cpu cortex-a72 \
	-kernel thirdparty/Image \
	-initrd thirdparty/initramfs.cpio.gz \
	-serial mon:stdio \
	-m 2G \
	-monitor telnet:127.0.0.1:55555,server,nowait;\
	-smp 4


$(BOOTLOADER)clean:
	$(RM) $(shell find build/src -name '*.o') $(BOOTLOADER)

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
thirdparties: $(BUILD)/thirdparty/initramfs.cpio.gz $(BUILD)/thirdparty/Image
	$(info Thirdparty builds finished !)

.PHONY: distclean
distclean:
	rm -rf $(BUILD)/busybox-* $(BUILD)/linux-*

.PHONY: thirdpartyclean
thirdpartyclean:
	rm -rf $(BUILD)/thirdparty

$(BUILD)/busybox-1.35.0:
	curl -LO https://busybox.net/downloads/busybox-1.35.0.tar.bz2 --output $(BUILD)/busybox-1.35.0.tar.bz2
	tar jxvf $(BUILD)/busybox-1.35.0.tar.bz2 -C $(BUILD)

$(BUILD)/linux-5.19.17:
	wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.19.17.tar.xz --output-document=$(BUILD)/linux-5.19.17.tar.xz
	tar -Jxvf $(BUILD)/linux-5.19.17.tar.xz

$(BUILD)/linux-5.19.17/.config: $(BUILD)/linux-5.19.17
	cp cfg/linux_cfg $@

$(BUILD)/linux-5.19.17/arch/arm64/boot/Image: $(BUILD)/linux-5.19.17/.config dependences
	cd $(BUILD)/linux-5.19.17/ && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image -j $(NCORE) && cd ..

$(BUILD)/thirdparty:
	mkdir -p $(BUILD)/thirdparty

$(BUILD)/thirdparty/Image: $(BUILD)/linux-5.19.17/arch/arm64/boot/Image thirdparty
	cp $< $@

$(BUILD)/busybox-1.35.0/.config: $(BUILD)/busybox-1.35.0 dependences
	cd $(BUILD)/busybox-1.35.0/ && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
	cp cfg/busybox_cfg $@

$(BUILD)/busybox-1.35.0/_install: $(BUILD)/busybox-1.35.0/.config dependences
	cd $(BUILD)/busybox-1.35.0 && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- install -j $(NCORE)

$(BUILD)/busybox-1.35.0/initramfs: $(BUILD)/busybox-1.35.0/_install dependences
	mkdir -pv $@
	cd $@ && for i in bin sbin etc proc sys usr/bin usr/sbin; do mkdir -pv $$i; done && cp -a ../_install/* .

$(BUILD)/busybox-1.35.0/initramfs/init: $(BUILD)/busybox-1.35.0/initramfs dependences
	# cd $(BUILD)/busybox-1.35.0 && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- install -j $(NCORE)
	cp cfg/busybox_init $@
	chmod +x $@

$(BUILD)/busybox-1.35.0/initramfs.cpio.gz: $(BUILD)/busybox-1.35.0/initramfs/init
	cd $(BUILD)/busybox-1.35.0/initramfs && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

$(BUILD)/thirdparty/initramfs.cpio.gz: $(BUILD)/busybox-1.35.0/initramfs.cpio.gz $(BUILD)/thirdparty
	cp $< $@

################################################################################
# Dependences
################################################################################
.PHONY: dependences
dependences:
		sudo apt install -y gcc-aarch64-linux-gnu
		sudo apt install -y bison
		sudo apt install qemu-system-arm
