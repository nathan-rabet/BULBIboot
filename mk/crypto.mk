# Bootloader signature
$(BUILD)/$(BOOTLOADER_SIG_HEX): $(BUILD)/$(BOOTLOADER_SIG)
	mkdir -p $(BUILD)
	xxd -p -c 16 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(BOOTLOADER_SIG): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG) $(BUILD)/$(BOOTLOADER_PEM_PRIVATE)
	mkdir -p $(BUILD)
	openssl dgst -sha256 -sign $(BUILD)/$(BOOTLOADER_PEM_PRIVATE) < $< > $@

$(BUILD)/$(BOOTLOADER_DER_PUBLIC_HEX): $(BUILD)/$(BOOTLOADER_DER_PUBLIC)
	mkdir -p $(BUILD)
	xxd -p -c 16 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(BOOTLOADER_DER_PUBLIC): $(BUILD)/$(BOOTLOADER_PEM_PRIVATE)
	mkdir -p $(BUILD)
	openssl rsa -in $< -pubout -outform DER -out $@

$(BUILD)/$(BOOTLOADER_PEM_PRIVATE):
	mkdir -p $(BUILD)
	openssl genrsa -out $@ 2048

# Kernel signature
$(BUILD)/$(KERNEL_SIG_HEX): $(BUILD)/$(KERNEL_SIG) $(BUILD)/thirdparty/$(ARCH)
	mkdir -p $(BUILD)
	xxd -p -c 16 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(KERNEL_SIG): $(BUILD)/$(KERNEL) $(BUILD)/$(KERNEL_PEM_PRIVATE) $(BUILD)/thirdparty/$(ARCH)
	mkdir -p $(BUILD)
	openssl dgst -sha256 -sign $(BUILD)/$(KERNEL_PEM_PRIVATE) < $< > $@ 

$(BUILD)/$(KERNEL_DER_PUBLIC_HEX): $(BUILD)/$(KERNEL_DER_PUBLIC) $(BUILD)/thirdparty/$(ARCH)
	mkdir -p $(BUILD)
	xxd -p -c 16 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@
	
$(BUILD)/$(KERNEL_DER_PUBLIC): $(BUILD)/$(KERNEL_PEM_PRIVATE) $(BUILD)/thirdparty/$(ARCH)
	mkdir -p $(BUILD)
	openssl rsa -in $< -pubout -outform DER -out $@

$(BUILD)/$(KERNEL_PEM_PRIVATE): $(BUILD)/thirdparty/$(ARCH)
	mkdir -p $(BUILD)
	openssl genrsa -out $@ 2048

# Encryption
$(BUILD)/$(DECRYPTOR_ELF): $(BUILD)/$(BOOTLOADER_DER_PUBLIC_HEX) $(BUILD)/$(BOOTLOADER_SIG_HEX) $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH_HEX) $(OBJS_DECRYPT) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)
	mkdir -p $(BUILD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS_DECRYPT) $(LIB_TOMCRYPT) $(LIB_TOMMATH) $(LIB_GCC)

$(BUILD)/$(DECRYPTOR_IMG): $(BUILD)/$(DECRYPTOR_ELF)
	mkdir -p $(BUILD)
	$(CROSS_COMPILE)objcopy -O binary $< $@

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY):
	mkdir -p $(BUILD)
	openssl rand -out $@ 32

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY) $(BUILD)/$(KERNEL_DER_PUBLIC_HEX) $(BUILD)/$(KERNEL_SIG_HEX) $(BUILD)/$(BOOTLOADER_IMG)
	mkdir -p $(BUILD)
	openssl enc -aes-256-cbc \
	-in $(BUILD)/$(BOOTLOADER_IMG) \
	-out $@ \
	-K $(shell xxd -p -c 256 $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY) | sed 's/\(..\)/\1/g') \
	-iv 00000000000000000000000000000000

# Hash
$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY)
	mkdir -p $(BUILD)
	openssl dgst -sha256 -binary -out $@ $<

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH_HEX): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH)
	mkdir -p $(BUILD)
	xxd -p -c 16 $< | sed 's/\(..\)/0x\1, /g' | sed '$$s/,$$//' > $@

$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_TXT): $(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY)
	mkdir -p $(BUILD)
	xxd -p -c 64 $< | sed 's/\(..\)/\1/g' > $@

.PHONY: cleancrypto
cleancrypto:
	$(RM) $(BUILD)/$(BOOTLOADER_SIG_HEX) \
	$(BUILD)/$(BOOTLOADER_SIG) \
	$(BUILD)/$(BOOTLOADER_DER_PUBLIC_HEX) \
	$(BUILD)/$(BOOTLOADER_DER_PUBLIC) \
	$(BUILD)/$(BOOTLOADER_PEM_PRIVATE) \
	$(BUILD)/$(KERNEL_SIG_HEX) \
	$(BUILD)/$(KERNEL_SIG) \
	$(BUILD)/$(KERNEL_DER_PUBLIC_HEX) \
	$(BUILD)/$(KERNEL_DER_PUBLIC) \
	$(BUILD)/$(KERNEL_PEM_PRIVATE) \
	$(BUILD)/$(DECRYPTOR_ELF) \
	$(BUILD)/$(DECRYPTOR_IMG) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_HASH_HEX) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG_KEY_TXT) \
	$(BUILD)/$(ENCRYPTED_BOOTLOADER_IMG)

