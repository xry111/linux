// SPDX-License-Identifier: GPL-2.0
/*
 * Support for Kernel relocation at boot time
 *
 * Copyright (C) 2022 Loongson Technology Corporation Limited
 *
 * Derived from MIPS:
 * Copyright (C) 2015, Imagination Technologies Ltd.
 */

#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/start_kernel.h>
#include <linux/of_fdt.h>
#include <linux/printk.h>
#include <linux/panic_notifier.h>
#include <asm/bootinfo.h>
#include <asm/early_ioremap.h>
#include <asm/inst.h>
#include <asm/sections.h>

#define RELOCATED(x) ((void *)((long)x + offset))

extern long __rela_dyn_start;
extern long __rela_dyn_end;

#ifdef CONFIG_RANDOMIZE_BASE

static inline __init unsigned long rotate_xor(unsigned long hash,
					      const void *area, size_t size)
{
	size_t i;
	unsigned long *ptr = (unsigned long *)area;

	for (i = 0; i < size / sizeof(hash); i++) {
		/* Rotate by odd number of bits and XOR. */
		hash = (hash << ((sizeof(hash) * 8) - 7)) | (hash >> 7);
		hash ^= ptr[i];
	}

	return hash;
}

static inline __init unsigned long get_random_boot(void)
{
	unsigned long entropy = random_get_entropy();
	unsigned long hash = 0;

	/* Attempt to create a simple but unpredictable starting entropy. */
	hash = rotate_xor(hash, linux_banner, strlen(linux_banner));

	/* Add in any runtime entropy we can get */
	hash = rotate_xor(hash, &entropy, sizeof(entropy));

	return hash;
}

static inline __init bool kaslr_disabled(void)
{
	char *str;

	str = strstr(boot_command_line, "nokaslr");
	if (str == boot_command_line || (str > boot_command_line && *(str - 1) == ' '))
		return true;

	return false;
}

/* Choose a new address for the kernel */
static inline void __init *determine_relocation_address(void)
{
	unsigned long kernel_length;
	void *dest = _text;
	unsigned long offset;

	if (kaslr_disabled())
		return dest;

	kernel_length = (long)_end - (long)_text;

	offset = get_random_boot() << 16;
	offset &= (CONFIG_RANDOMIZE_BASE_MAX_OFFSET - 1);
	if (offset < kernel_length)
		offset += ALIGN(kernel_length, 0xffff);

	return RELOCATED(dest);
}

#else

/*
 * Choose a new address for the kernel, for now we'll hard
 * code the destination.
 */
static inline void __init *determine_relocation_address(void)
{
	return (void *)(CACHE_BASE + 0x02000000);
}

#endif

static inline int __init relocation_addr_valid(void *loc_new)
{
	if ((unsigned long)loc_new & 0x0000ffff) {
		/* Inappropriately aligned new location */
		return 0;
	}
	if ((unsigned long)loc_new < (unsigned long)_end) {
		/* New location overlaps original kernel */
		return 0;
	}
	return 1;
}

static inline void __init update_kaslr_offset(unsigned long *addr, long offset)
{
	unsigned long *new_addr = (unsigned long *)RELOCATED(addr);

	*new_addr = (unsigned long)offset;
}

void *__init relocate_kernel(void)
{
	Elf64_Rela *rela, *rela_end;
	void *loc_new;
	unsigned long kernel_length;
	long offset = 0;
	int res = 1;
	/* Default to original kernel entry point */
	void *kernel_entry = start_kernel;

	/* Boot command line was passed in FDT */
	early_init_dt_scan(early_ioremap(fw_arg1, SZ_64K));

	kernel_length = (long)(_end) - (long)(_text);

	loc_new = determine_relocation_address();

	/* Sanity check relocation address */
	if (relocation_addr_valid(loc_new))
		offset = (unsigned long)loc_new - (unsigned long)(_text);

	if (offset) {
		/* Copy the kernel to it's new location */
		memcpy(loc_new, _text, kernel_length);

		/* Sync the caches ready for execution of new kernel */
		__asm__ __volatile__ (
			"ibar 0 \t\n"
			"dbar 0 \t\n");

		rela = (Elf64_Rela *)RELOCATED(&__rela_dyn_start);
		rela_end = (Elf64_Rela *)RELOCATED(&__rela_dyn_end);

		for ( ; rela < rela_end; rela++) {
			Elf64_Addr addr = rela->r_offset;
			Elf64_Addr relocated_addr = rela->r_addend;

			if (rela->r_info != R_LARCH_RELATIVE)
				continue;

			if (relocated_addr >= VMLINUX_LOAD_ADDRESS)
				relocated_addr = RELOCATED(relocated_addr);

			*(Elf64_Addr *)RELOCATED(addr) = relocated_addr;

		}

		/* The current thread is now within the relocated image */
		__current_thread_info = RELOCATED(__current_thread_info);

		/* Return the new kernel's entry point */
		kernel_entry = RELOCATED(start_kernel);

		/* Error may occur before, so keep it at last */
		update_kaslr_offset(&__kaslr_offset, offset);
	}
out:
	return kernel_entry;
}

/*
 * Show relocation information on panic.
 */
static void show_kernel_relocation(const char *level)
{
	if (__kaslr_offset > 0) {
		printk(level);
		pr_cont("Kernel relocated offset @ 0x%lx\n", __kaslr_offset);
		pr_cont(" .text @ 0x%lx\n", (unsigned long)&_text);
		pr_cont(" .data @ 0x%lx\n", (unsigned long)&_sdata);
		pr_cont(" .bss  @ 0x%lx\n", (unsigned long)&__bss_start);
	}
}

static int kernel_location_notifier_fn(struct notifier_block *self,
				       unsigned long v, void *p)
{
	show_kernel_relocation(KERN_EMERG);
	return NOTIFY_DONE;
}

static struct notifier_block kernel_location_notifier = {
	.notifier_call = kernel_location_notifier_fn
};

static int __init register_kernel_offset_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &kernel_location_notifier);
	return 0;
}
__initcall(register_kernel_offset_dumper);
