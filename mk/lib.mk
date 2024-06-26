################################################################################
# libtomcrypt
################################################################################
.PHONY: libtomcrypt
libtomcrypt: $(LIB_TOMCRYPT)
	$(info Libtomcrypt build finished !)

$(LIB_TOMCRYPT): lib/libtomcrypt $(LIB_TOMMATH)
	$(MAKE) -C lib/libtomcrypt install \
	PREFIX=$(shell pwd)/$(BUILD)/lib/libtomcrypt \
	IGNORE_SPEED=1 \
	CFLAGS="-g -D USE_LTM -D ARGTYPE=4 -I$(shell pwd)/$(LIB_TOMMATH_HEADERS) -fno-stack-protector"
	EXTRALIBS=$(LIB_TOMMATH)

################################################################################
# libtommath
################################################################################
.PHONY: libtommath
libtommath: $(LIB_TOMMATH)
	$(info Libtommath build finished !)

$(LIB_TOMMATH): lib/libtommath
	$(MAKE) -C lib/libtommath install \
	PREFIX=$(shell pwd)/$(BUILD)/lib/libtommath \
	IGNORE_SPEED=1 \
	CFLAGS="-g -D ARGTYPE=4 -D MP_NO_DEV_URANDOM -U__linux__ -fno-stack-protector"

.PHONY: libclean
libclean:
	$(MAKE) -C lib/libtomcrypt clean PREFIX=$(shell pwd)/$(BUILD)/lib/libtomcrypt
	$(MAKE) -C lib/libtommath clean PREFIX=$(shell pwd)/$(BUILD)/lib/libtommath
	$(RM) -r $(BUILD)/lib/
