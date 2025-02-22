/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the low-level inversion functions.
 *
 * @&version $Id$
 * @ingroup fp
 */

#include "relic_bn.h"
#include "low/relic_bn_low.h"
#include "relic_fp.h"
#include "low/relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smbm_low(const dig_t *a) {
	bn_st e;
	dig_t t[RLC_FP_DIGS];

	bn_make(&e, RLC_FP_DIGS);

	e.used = RLC_FP_DIGS;
	dv_copy(e.dp, fp_prime_get(), RLC_FP_DIGS);
	bn_rsh1_low(e.dp, e.dp, RLC_FP_DIGS);
#if AUTO == ALLOC
	fp_exp(t, a, &e);
#else
	fp_exp(t, (const fp_t)a, &e);
#endif

	int r = (fp_cmp_dig(t, 1) == RLC_EQ);
	fp_negm_low(t, t);
	r = RLC_SEL(r, -(fp_cmp_dig(t, 1) == RLC_EQ), !r);

	bn_clean(&e);

	return r;
}
