#
# arch/loongarch/boot/Makefile
#
# Copyright (C) 2020-2022 Loongson Technology Corporation Limited
#

drop-sections := .comment .note .options .note.gnu.build-id
strip-flags   := $(addprefix --remove-section=,$(drop-sections)) -S

targets := vmlinux
quiet_cmd_strip = STRIP	  $@
      cmd_strip = $(STRIP) -s $@

$(obj)/vmlinux: vmlinux FORCE
	$(call if_changed,copy)
	$(call if_changed,strip)

targets += vmlinux.efi
quiet_cmd_eficopy = OBJCOPY $@
      cmd_eficopy = $(OBJCOPY) -O binary $(strip-flags) $< $@

$(obj)/vmlinux.efi: $(obj)/vmlinux FORCE
	$(call if_changed,eficopy)

# zboot
extra-y	+= boot.lds
$(obj)/boot.lds: $(obj)/vmlinux.bin FORCE
CPPFLAGS_boot.lds = $(KBUILD_CPPFLAGS) -DVMLINUZ_LOAD_ADDRESS=$(zload-y)

entry-y	= $(shell $(objtree)/arch/loongarch/tools/elf-entry $(obj)/vmlinux)
zload-y = $(shell $(objtree)/arch/loongarch/tools/calc_vmlinuz_load_addr \
				$(obj)/vmlinux.bin $(VMLINUX_LOAD_ADDRESS))

BOOT_HEAP_SIZE	:= 0x400000
BOOT_STACK_SIZE	:= 0x002000

KBUILD_AFLAGS := $(KBUILD_AFLAGS) -D__ASSEMBLY__ \
	-DBOOT_HEAP_SIZE=$(BOOT_HEAP_SIZE) \
	-DBOOT_STACK_SIZE=$(BOOT_STACK_SIZE)

KBUILD_CFLAGS := $(KBUILD_CFLAGS) -fpic -D__KERNEL__ \
	-DBOOT_HEAP_SIZE=$(BOOT_HEAP_SIZE) \
	-DBOOT_STACK_SIZE=$(BOOT_STACK_SIZE)

targets += vmlinux.bin
OBJCOPYFLAGS_vmlinux.bin := $(OBJCOPYFLAGS) -O binary $(strip-flags)
$(obj)/vmlinux.bin: $(obj)/vmlinux FORCE
	$(call if_changed,objcopy)

tool_$(CONFIG_KERNEL_GZIP)    = gzip
tool_$(CONFIG_KERNEL_BZIP2)   = bzip2_with_size
tool_$(CONFIG_KERNEL_LZ4)     = lz4_with_size
tool_$(CONFIG_KERNEL_LZMA)    = lzma_with_size
tool_$(CONFIG_KERNEL_LZO)     = lzo_with_size
tool_$(CONFIG_KERNEL_XZ)      = xzkern_with_size
tool_$(CONFIG_KERNEL_ZSTD)    = zstd22_with_size

targets += vmlinux.bin.z
$(obj)/vmlinux.bin.z: $(obj)/vmlinux.bin FORCE
	$(call if_changed,$(tool_y))

targets += $(notdir $(vmlinuzobjs-y))
vmlinuzobjs-y := $(obj)/zkernel.o $(obj)/decompress.o $(obj)/string.o
vmlinuzobjs-$(CONFIG_EFI_STUB) += $(objtree)/drivers/firmware/efi/libstub/lib.a
$(obj)/zkernel.o: $(obj)/vmlinux.bin.z
AFLAGS_zkernel.o = $(KBUILD_AFLAGS) -DVMLINUZ_LOAD_ADDRESS=$(zload-y) -DKERNEL_ENTRY=$(entry-y)

quiet_cmd_zld = LD      $@
      cmd_zld = $(LD) $(KBUILD_LDFLAGS) -T $< $(vmlinuzobjs-y) -o $@

targets += vmlinuz
$(obj)/vmlinuz: $(src)/boot.lds $(vmlinuzobjs-y) FORCE
	$(call if_changed,zld)
	$(call if_changed,strip)

targets += vmlinuz.efi
$(obj)/vmlinuz.efi: $(obj)/vmlinuz FORCE
	$(call if_changed,eficopy)
