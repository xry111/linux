// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Xi Ruoyao <xry111@xry111.site>. All Rights Reserved.
 */
#include <linux/types.h>

#include "../../../../lib/vdso/getrandom.c"

typeof(__cvdso_getrandom) __vdso_getrandom;

ssize_t __vdso_getrandom(void *buffer, size_t len, unsigned int flags,
			 void *opaque_state, size_t opaque_len)
{
	return __cvdso_getrandom(buffer, len, flags, opaque_state,
				 opaque_len);
}

typeof(__cvdso_getrandom) getrandom
	__attribute__((weak, alias("__vdso_getrandom")));
