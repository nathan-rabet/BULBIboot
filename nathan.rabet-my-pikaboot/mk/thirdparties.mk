BUSYBOX=busybox-1.35.0
LINUX=linux-5.19.17

$(BUILD)/$(BUSYBOX):
	curl -LO https://busybox.net/downloads/$(BUSYBOX).tar.bz2 --output $(BUILD)/$(BUSYBOX).tar.bz2
	tar jxvf $(BUILD)/$(BUSYBOX).tar.bz2 -C $(BUILD)
	cp cfg/busybox_cfg $(BUILD)/$(BUSYBOX)/.config

$(BUILD)/$(LINUX):
	wget https://cdn.kernel.org/pub/linux/kernel/v5.x/$(LINUX).tar.xz --output-document=$(BUILD)/$(LINUX).tar.xz
	tar -Jxvf $(BUILD)/$(LINUX).tar.xz

$(BUILD)/$(LINUX)/.config: $(BUILD)/$(LINUX)
	cp cfg/linux_cfg $@

$(BUILD)/$(LINUX)/arch/$(ARCH)/boot/Image: $(BUILD)/$(LINUX)/.config
	cd $(BUILD)/$(LINUX)/ && make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) Image -j $(NCORE) && cd ..

$(BUILD)/thirdparty/$(ARCH):
	mkdir -p $(BUILD)/thirdparty
	mkdir -p $@

$(BUILD)/$(KERNEL): $(BUILD)/$(LINUX)/arch/$(ARCH)/boot/Image $(BUILD)/thirdparty/$(ARCH)
	cp $< $@

$(BUILD)/$(BUSYBOX)/.config: $(BUILD)/$(BUSYBOX)
	cd $(BUILD)/$(BUSYBOX)/ && make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) defconfig -j $(NCORE)
	cp cfg/busybox_cfg $@

$(BUILD)/$(BUSYBOX)/_install: $(BUILD)/$(BUSYBOX)/.config
	cd $(BUILD)/$(BUSYBOX) && make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) install -j $(NCORE)

$(BUILD)/$(BUSYBOX)/initramfs: $(BUILD)/$(BUSYBOX)/_install
	mkdir -pv $@
	cd $@ && for i in bin sbin etc proc sys usr/bin usr/sbin; do mkdir -pv $$i; done && cp -a ../_install/* .

$(BUILD)/$(BUSYBOX)/initramfs/init: $(BUILD)/$(BUSYBOX)/initramfs
	cd $(BUILD)/$(BUSYBOX) && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) install
	cp cfg/busybox_init $@
	chmod +x $@

$(BUILD)/$(BUSYBOX)/initramfs.cpio.gz: $(BUILD)/$(BUSYBOX)/initramfs/init
	cd $(BUILD)/$(BUSYBOX)/initramfs && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

$(BUILD)/$(INITRD): $(BUILD)/$(BUSYBOX)/initramfs.cpio.gz $(BUILD)/thirdparty/$(ARCH)
	cp $< $@
