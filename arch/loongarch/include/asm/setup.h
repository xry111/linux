/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef _LOONGARCH_SETUP_H
#define _LOONGARCH_SETUP_H

#include <linux/types.h>
#include <uapi/asm/setup.h>

#define VECSIZE 0x200

struct handler_reloc;

extern struct handler_reloc *eentry_reloc[];
extern unsigned long eentry;
extern unsigned long tlbrentry;
extern char init_command_line[COMMAND_LINE_SIZE];
extern void tlb_init(int cpu);
extern void cpu_cache_init(void);
extern void cache_error_setup(void);
extern void per_cpu_trap_init(int cpu);
extern void set_handler(unsigned long exccode, void *addr);
extern void set_merr_handler(unsigned long offset, void *addr, unsigned long len);
extern void reloc_handler(unsigned long handler, struct handler_reloc *rel);

#endif /* __SETUP_H */
