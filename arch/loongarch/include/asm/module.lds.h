/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020-2022 Loongson Technology Corporation Limited */
SECTIONS {
	. = ALIGN(4);
	.plt : { BYTE(0) }
	.plt.idx : { BYTE(0) }
	.got : { HIDDEN(_GLOBAL_OFFSET_TABLE_ = .); BYTE(0) }
}
