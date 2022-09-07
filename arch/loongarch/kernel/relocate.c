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
#include <linux/printk.h>
#include <linux/panic_notifier.h>
#include <asm/bootinfo.h>
#include <asm/inst.h>
#include <asm/sections.h>

#define RELOCATED(x) ((void *)((long)x + offset))

extern long __rela_dyn_start;
extern long __rela_dyn_end;

/*
 * Choose a new address for the kernel, for now we'll hard
 * code the destination.
 */
static inline void __init *determine_relocation_address(void)
{
	return (void *)(CACHE_BASE + 0x02000000);
}

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

void *__init relocate_kernel(void)
{
	Elf64_Rela *rela, *rela_end;
	void *loc_new;
	unsigned long kernel_length;
	long offset = 0;
	int res = 1;
	/* Default to original kernel entry point */
	void *kernel_entry = start_kernel;

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
	}
out:
	return kernel_entry;
}
