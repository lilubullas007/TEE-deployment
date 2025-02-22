/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of multiplication in a nonic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "low/relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

void fp9_mul_basic(fp9_t c, const fp9_t a, const fp9_t b) {
	fp3_t v0, v1, v2, t0, t1, t2;

	fp3_null(v0);
	fp3_null(v1);
	fp3_null(v2);
	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);

	RLC_TRY {
		fp3_new(v0);
		fp3_new(v1);
		fp3_new(v2);
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);

		/* v0 = a_0b_0 */
		fp3_mul(v0, a[0], b[0]);

		/* v1 = a_1b_1 */
		fp3_mul(v1, a[1], b[1]);

		/* v2 = a_2b_2 */
		fp3_mul(v2, a[2], b[2]);

		/* t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp3_add(t0, a[1], a[2]);
		fp3_add(t1, b[1], b[2]);
		fp3_mul(t2, t0, t1);
		fp3_sub(t2, t2, v1);
		fp3_sub(t2, t2, v2);
		fp3_mul_nor(t0, t2);
		fp3_add(t2, t0, v0);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp3_add(t0, a[0], a[1]);
		fp3_add(t1, b[0], b[1]);
		fp3_mul(c[1], t0, t1);
		fp3_sub(c[1], c[1], v0);
		fp3_sub(c[1], c[1], v1);
		fp3_mul_nor(t0, v2);
		fp3_add(c[1], c[1], t0);

		/* c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp3_add(t0, a[0], a[2]);
		fp3_add(t1, b[0], b[2]);
		fp3_mul(c[2], t0, t1);
		fp3_sub(c[2], c[2], v0);
		fp3_add(c[2], c[2], v1);
		fp3_sub(c[2], c[2], v2);

		/* c_0 = t2 */
		fp3_copy(c[0], t2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free(t2);
		fp3_free(t1);
		fp3_free(t0);
		fp3_free(v2);
		fp3_free(v1);
		fp3_free(v0);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void fp9_mul_unr(dv9_t c, const fp9_t a, const fp9_t b) {
	dv3_t u0, u1, u2, u3;
	fp3_t t0, t1;

	dv3_null(u0);
	dv3_null(u1);
	dv3_null(u2);
	dv3_null(u3);
	fp3_null(t0);
	fp3_null(t1);

	RLC_TRY {
		dv3_new(u0);
		dv3_new(u1);
		dv3_new(u2);
		dv3_new(u3);
		fp3_new(t0);
		fp3_new(t1);

		/* v0 = a_0b_0, v1 = a_1b_1, v2 = a_2b_2,
		 * t0 = a_1 + a_2, t1 = b_1 + b_2,
		 * u4 = u1 + u2, u5 = u0 + u1, u6 = u0 + u2 */
#ifdef RLC_FP_ROOM
		fp3_muln_low(u0, a[0], b[0]);
		fp3_muln_low(u1, a[1], b[1]);
		fp3_muln_low(u2, a[2], b[2]);
		fp3_addm_low(t0, a[1], a[2]);
		fp3_addm_low(t1, b[1], b[2]);
		fp3_addc_low(c[0], u1, u2);
#else
		fp3_muln_low(u0, a[0], b[0]);
		fp3_muln_low(u1, a[1], b[1]);
		fp3_muln_low(u2, a[2], b[2]);
		fp3_addm_low(t0, a[1], a[2]);
		fp3_addm_low(t1, b[1], b[2]);
		fp3_addc_low(c[0], u1, u2);
#endif
		/* t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp3_muln_low(u3, t0, t1);
		fp3_subc_low(u3, u3, c[0]);
		fp3_nord_low(c[0], u3);
		fp3_addc_low(c[0], c[0], u0);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp3_addm_low(t0, a[0], a[1]);
		fp3_addm_low(t1, b[0], b[1]);
		fp3_addc_low(c[1], u0, u1);

		fp3_muln_low(u3, t0, t1);
		fp3_subc_low(u3, u3, c[1]);
		fp3_nord_low(c[2], u2);
		fp3_addc_low(c[1], u3, c[2]);

		/* c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp3_addm_low(t0, a[0], a[2]);
		fp3_addm_low(t1, b[0], b[2]);
		fp3_addc_low(c[2], u0, u2);

		fp3_muln_low(u3, t0, t1);
		fp3_subc_low(u3, u3, c[2]);
		fp3_addc_low(c[2], u3, u1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free(u0);
		dv3_free(u1);
		dv3_free(u2);
		dv3_free(u3);
		fp3_free(t0);
		fp3_free(t1);
	}
}

void fp9_mul_lazyr(fp9_t c, const fp9_t a, const fp9_t b) {
	dv9_t t;

	dv9_null(t);

	RLC_TRY {
		dv9_new(t);
		fp9_mul_unr(t, a, b);
		fp3_rdcn_low(c[0], t[0]);
		fp3_rdcn_low(c[1], t[1]);
		fp3_rdcn_low(c[2], t[2]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv9_free(t);
	}
}

#endif

void fp9_mul_dxs(fp9_t c, const fp9_t a, const fp9_t b) {
	fp3_t v0, v1, t0, t1, t2;

	fp3_null(v0);
	fp3_null(v1);
	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);

	RLC_TRY {
		fp3_new(v0);
		fp3_new(v1);
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);

		/* v0 = a_0b_0 */
		fp3_mul(v0, a[0], b[0]);

		/* v1 = a_1b_1 */
		fp3_mul(v1, a[1], b[1]);

		/* v2 = a_2b_2 = 0 */

		/* t2 (c0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp3_add(t0, a[1], a[2]);
		fp3_mul(t0, t0, b[1]);
		fp3_sub(t0, t0, v1);
		fp3_mul_nor(t2, t0);
		fp3_add(t2, t2, v0);

		/* c1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp3_add(t0, a[0], a[1]);
		fp3_add(t1, b[0], b[1]);
		fp3_mul(c[1], t0, t1);
		fp3_sub(c[1], c[1], v0);
		fp3_sub(c[1], c[1], v1);

		/* c2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp3_add(t0, a[0], a[2]);
		fp3_mul(c[2], t0, b[0]);
		fp3_sub(c[2], c[2], v0);
		fp3_add(c[2], c[2], v1);

		/* c0 = t2 */
		fp3_copy(c[0], t2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free(v0);
		fp3_free(v1);
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
	}
}

void fp9_mul_art(fp9_t c, const fp9_t a) {
	fp3_t t0;

	fp3_null(t0);

	RLC_TRY {
		fp3_new(t0);

		/* (a_0 + a_1 * v + a_2 * v^2) * v = a_2 + a_0 * v + a_1 * v^2 */
		fp3_copy(t0, a[0]);
		fp3_mul_nor(c[0], a[2]);
		fp3_copy(c[2], a[1]);
		fp3_copy(c[1], t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free(t0);
	}
}
