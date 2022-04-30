/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Format of an instruction in memory.
 *
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _UAPI_ASM_INST_H
#define _UAPI_ASM_INST_H

#include <asm/bitfield.h>

enum reg1i20_op {
	lu12iw_op	= 0x0a,
	lu32id_op	= 0x0b,
};

enum reg2i12_op {
	lu52id_op	= 0x0c,
};

enum reg2i16_op {
	jirl_op		= 0x13,
};

struct reg1i20_format {
	__BITFIELD_FIELD(unsigned int opcode : 7,
	__BITFIELD_FIELD(unsigned int simmediate : 20,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))
};

struct reg2i12_format {
	__BITFIELD_FIELD(unsigned int opcode : 10,
	__BITFIELD_FIELD(signed int simmediate : 12,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i16_format {
	__BITFIELD_FIELD(unsigned int opcode : 6,
	__BITFIELD_FIELD(unsigned int simmediate : 16,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

union loongarch_instruction {
	unsigned int word;
	struct reg1i20_format reg1i20_format;
	struct reg2i12_format reg2i12_format;
	struct reg2i16_format reg2i16_format;
};

#define LOONGARCH_INSN_SIZE	sizeof(union loongarch_instruction)

#endif /* _UAPI_ASM_INST_H */
