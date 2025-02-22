/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2011 RELIC Authors
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
 * Implementation of the low-level trace function.
 *
 * @ingroup fb
 */

#include "relic_fb.h"
#include "low/relic_fb_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fb_trcn_low(const dig_t *a) {
	int ta, tb, tc;
	dig_t r;

	fb_poly_get_trc(&ta, &tb, &tc);

#if ALLOC == AUTO
	r = fb_get_bit(a, ta);
	if (tb != -1) {
		r ^= fb_get_bit(a, tb);
	}
	if (tc != -1) {
		r ^= fb_get_bit(a, tc);
	}
#else
	r = fb_get_bit((const fb_t)a, ta);
	if (tb != -1) {
		r ^= fb_get_bit((const fb_t)a, tb);
	}
	if (tc != -1) {
		r ^= fb_get_bit((const fb_t)a, tc);
	}
#endif

	return r;
}
