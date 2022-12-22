$(BUILD)/$(BOOTLOADER_ELF): $(BUILD)/$(KERNEL_DER_PUBLIC_HEX) $(BUILD)/$(KERNEL_SIG_HEX) $(OBJS_CORE) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)
	$(LD) $(LDFLAGS) -o $@ $(OBJS_CORE) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)

$(BUILD)/$(BOOTLOADER_IMG): $(BUILD)/$(BOOTLOADER_ELF)
	$(CROSS_COMPILE)objcopy -O binary $< $@

$(BUILD)/$(PFLASH_BIN): $(BUILD)/$(BOOTLOADER_IMG) $(BUILD)/$(KERNEL)
	$(V)dd if=/dev/zero of=$@ bs=1M count=$(PFLASH_LEN_MB)
	$(V)dd if=$(BUILD)/$(BOOTLOADER_IMG) of=$@ conv=notrunc bs=1M count=10
	$(V)dd if=$(BUILD)/$(KERNEL) of=$@ conv=notrunc bs=1M seek=$(KERNEL_BIN_OFFSET_MB)

$(BUILD)/$(ENCRYPTED_PFLASH_BIN): $(BUILD)/$(DECRYPTOR_IMG) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) $(BUILD)/$(KERNEL)
	$(V)dd if=/dev/zero of=$@ bs=1M count=$(PFLASH_LEN_MB)
	$(V)dd if=$(BUILD)/$(DECRYPTOR_IMG) of=$@ conv=notrunc bs=1M count=$(BOOTLOADER_BIN_OFFSET_MB)
	$(V)dd if=$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) of=$@ conv=notrunc bs=1M seek=$(BOOTLOADER_BIN_OFFSET_MB) count=20
	$(V)dd if=$(BUILD)/$(KERNEL) of=$@ conv=notrunc bs=1M seek=$(KERNEL_BIN_OFFSET_MB)


.PHONY: cleanpflash
cleanpflash:
	$(RM) $(BUILD)/$(PFLASH_BIN) \
	$(BUILD)/$(ENCRYPTED_PFLASH_BIN) \
	$(BUILD)/$(BOOTLOADER_ELF) \
	$(BUILD)/$(BOOTLOADER_IMG)
