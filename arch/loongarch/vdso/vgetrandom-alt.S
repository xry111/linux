// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Xi Ruoyao <xry111@xry111.site>. All Rights Reserved.
 *
 */

#include <asm/alternative-asm.h>
#include <asm/cpu.h>
#include <asm/unistd.h>
#include <asm/regdef.h>
#include <linux/linkage.h>

SYM_FUNC_START(__vdso_getrandom)
	ALTERNATIVE	__stringify(li.w a7, __NR_getrandom; syscall 0; jr ra), \
			"b __vdso_getrandom_lsx", CPU_FEATURE_LSX
SYM_FUNC_END(__vdso_getrandom)

.weak	getrandom
.set	getrandom, __vdso_getrandom
