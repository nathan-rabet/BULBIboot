include generic_flags.mk

srcs-y:=

# Convert .c and .S files to .o files in objs
objs:=$(patsubst %.c,%.c.o,$(srcs-y))
objs:=$(patsubst %.S,%.S.o,$(objs))

.PHONY: all
all: my_bootloader.img my_bootloader.dump pflash.bin
	$(info BUILD COMPLETED)

%.c.o: %.c
	$(V)$(CC) $(CFLAGS) $^ -o $@

%.S.o: %.S
	$(V)$(AS) $(SFLAGS) $^ -o $@

%.ld: %.lds
	$(V)$(AS) $^ -o $@

.PRECIOUS: %.elf
%.elf: $(objs)
	$(V)$(LD) $(LDFLAGS) $^ -o $@

.PRECIOUS: %.dump
%.dump: %.elf
	$(V)$(OBJDUMP) -D $^ > $@

.PRECIOUS: %.img
%.img: %.elf
	$(OBJCOPY) -O binary $< $@

.PRECIOUS: pflash.bin
pflash.bin: my_bootloader.img
	$(V)dd if=/dev/zero of=$@ bs=1M count=512
	$(V)dd if=$< of=$@ conv=notrunc bs=1M count=20
	$(V)dd if=$(KERNEL) of=$@ conv=notrunc bs=1M seek=50

.PHONY: clean
clean:
	rm -rf *.elf *.bin *.o */*.o */*/*.o *.img *.dump
