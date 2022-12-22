
include mk/common.mk

.PHONY: images
images: $(BUILD)/$(DECRYPTOR_IMG) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG)
	$(info Images generated successfully)

.PHONY: boot
boot: $(BOOT_IMG) $(BUILD)/$(INITRD) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_TXT)
	qemu-system-aarch64 \
	-machine virt,virtualization=on,secure=on \
	-nographic \
	-cpu cortex-a72 \
	-kernel $(BOOT_IMG) \
	-initrd $(BUILD)/$(INITRD) \
	-serial pty \
	-m 2G \
	-smp 1 \
	-d in_asm \
	-D qemu.log \
	$(QEMU_ADDITIONAL_FLAGS)

.PHONY: boot_gdb
boot_gdb: COPTIONS += -D DEBUG
boot_gdb: QEMU_ADDITIONAL_FLAGS=-gdb tcp::6666 -S
boot_gdb: boot
	
################################################################################
# Pflash
################################################################################
.PHONY: pflash
pflash: $(BUILD)/$(PFLASH_BIN)
	$(info Pflash generated successfully)

.PHONY: pflash_encrypted
pflash_encrypted: $(BUILD)/$(ENCRYPTED_PFLASH_BIN)
	$(info Encrypted pflash generated successfully)

include mk/pflash.mk

################################################################################
# Thirdparties
################################################################################
.PHONY: thirdparties
thirdparties: $(BUILD)/$(INITRD) $(BUILD)/$(KERNEL)
	$(info Thirdparty builds finished !)

include mk/thirdparties.mk

################################################################################
# Crypto
################################################################################
.PHONY: crypto
crypto: $(BUILD)/$(BOOTLADER_DER_KEY) $(BUILD)/$(BOOTLOADER_SIG) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY)
	$(info Bootloader public DER, signature and encrypted bootloader image key generated !)

include mk/crypto.mk
################################################################################
# libraries
################################################################################

include mk/lib.mk

################################################################################
# Objects files
################################################################################

include mk/objs.mk

################################################################################
# Clean
################################################################################
.PHONY: clean
clean: cleancrypto cleanpflash
	$(RM) -r $(BUILD)/src/
	$(info Clean finished !)

.PHONY: clean_clean
clean_clean: clean libclean
	$(info Clean-clean finished !)

################################################################################
# Dependences
################################################################################
.PHONY: dependences
dependences:
	bash dependences.sh
	$(info Dependences installed successfully!)
