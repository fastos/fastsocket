/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * test.c header
 *
 * Copyright 2009-2011 Christian Lamparter <chunkeey@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CARL9170USER_TEST_H
#define __CARL9170USER_TEST_H

#include "carlu.h"

void carlu_loopback_test(struct carlu *ar, const unsigned int total_runs,
			 const unsigned int interval, const unsigned int min_len,
			 const unsigned int max_len);

int carlu_gpio_test(struct carlu *ar);
int carlu_random_test(struct carlu *ar);

#endif /* __CARL9170USER_TEST_H */
