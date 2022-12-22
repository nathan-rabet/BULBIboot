$(BUILD)/%.o: COPTIONS += -D RAM_SIZE=$(RAM_SIZE_BYTES)
$(BUILD)/%.o: COPTIONS += -D PFLASH_LEN=$(shell echo $$(( $(PFLASH_LEN_MB) * 1024 * 1024 )))
$(BUILD)/%.o: COPTIONS += -D BOOTLOADER_IMG_OFFSET=$(shell echo $$(($(BOOTLOADER_BIN_OFFSET_MB) * 1024 * 1024)))
$(BUILD)/%.o: COPTIONS += -D ENCRYPTED_BOOTLOADER_IMG_LEN=$(shell wc -c $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) | cut -d' ' -f1)
$(BUILD)/%.o: COPTIONS += -D BOOTLOADER_IMG_LEN=$(shell wc -c $(BUILD)/$(BOOTLOADER_IMG) | cut -d' ' -f1)
$(BUILD)/%.o: COPTIONS += -D BOOTLOADER_CRC=$(shell crc32 $(BUILD)/$(BOOTLOADER_IMG) | sed 's/^\(.*\)$$/0x\1/')
$(BUILD)/%.o: COPTIONS += -D KERNEL_IMG_LEN=$(shell wc -c $(BUILD)/$(KERNEL) | cut -d' ' -f1)
$(BUILD)/%.o: COPTIONS += -D KERNEL_CRC=$(shell crc32 $(BUILD)/$(KERNEL) | sed 's/^\(.*\)$$/0x\1/')
$(BUILD)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(COPTIONS) $(CSTD) $(CINCLUDE) $(CDEBUG) $(CERROR) $(COPTIM) -c $< -o $@

$(BUILD)/%.o: %.S
	mkdir -p $(dir $@)
	$(CC) $(COPTIONS) $(CSTD) $(CINCLUDE) $(CDEBUG) $(CERROR) $(COPTIM) -c $< -o $@
