NCORE?=8

boot_mock:
	qemu-system-aarch64 \
	-machine virt \
	-cpu cortex-a72 \
	-kernel thirdparty/Image \
	-initrd thirdparty/initramfs.cpio.gz \
	-serial mon:stdio \
	-m 2G \
	-monitor telnet:127.0.0.1:55555,server,nowait;\
	-smp 4

.PHONY: thirdparties
thirdparties: thirdparty/initramfs.cpio.gz thirdparty/Image
	$(info Thirdparty builds finished !)

.PHONY: distclean
distclean:
	rm -rf busybox-* linux-*

.PHONY: clean
clean:
	rm -rf thirdparty

busybox-1.35.0:
	curl -LO https://busybox.net/downloads/busybox-1.35.0.tar.bz2
	tar jxvf busybox-1.35.0.tar.bz2

linux-5.19.17:
	wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.19.17.tar.xz
	tar -Jxvf linux-5.19.17.tar.xz

linux-5.19.17/.config: linux-5.19.17
	cp cfg/linux_cfg $@

linux-5.19.17/arch/arm64/boot/Image: dependences linux-5.19.17/.config
	cd linux-5.19.17/ && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image -j $(NCORE) && cd ..

thirdparty:
	mkdir -p thirdparty

thirdparty/Image: linux-5.19.17/arch/arm64/boot/Image thirdparty
	cp $< $@

busybox-1.35.0/.config: dependences busybox-1.35.0
	cd busybox-1.35.0/ && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
	cp cfg/busybox_cfg $@

busybox-1.35.0/_install: dependences busybox-1.35.0/.config
	cd busybox-1.35.0 && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- install -j $(NCORE)

busybox-1.35.0/initramfs: dependences busybox-1.35.0/_install
	mkdir -pv $@
	cd $@ && for i in bin sbin etc proc sys usr/bin usr/sbin; do mkdir -pv $$i; done && cp -a ../_install/* .

busybox-1.35.0/initramfs/init: dependences busybox-1.35.0/initramfs
	# cd busybox-1.35.0 && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- install -j $(NCORE)
	cp cfg/busybox_init $@
	chmod +x $@

busybox-1.35.0/initramfs.cpio.gz: busybox-1.35.0/initramfs/init
	cd busybox-1.35.0/initramfs && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

thirdparty/initramfs.cpio.gz: busybox-1.35.0/initramfs.cpio.gz thirdparty
	cp $< $@

.PHONY: dependences
dependences:
		sudo apt install -y gcc-aarch64-linux-gnu
		sudo apt install -y bison
		sudo apt install qemu-system-arm
