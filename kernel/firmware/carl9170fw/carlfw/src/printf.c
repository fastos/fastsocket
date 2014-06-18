/*
 * Copyright (C) 2004,2008  Kustaa Nyholm
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "carl9170.h"
#include "printf.h"

#ifdef CONFIG_CARL9170FW_PRINTF
static char *bf;
static char buf[12];
static unsigned int num;
static char uc;
static char zs;

static void out(const char c)
{
	*bf++ = c;
}

static void outDgt(const char dgt)
{
	out(dgt + (dgt < 10 ? '0' : (uc ? 'A' : 'a') - 10));
	zs = 1;
}

static void divOut(const unsigned int d)
{
	unsigned char dgt = 0;

	while (num >= d) {
		num -= d;
		dgt++;
	}

	if (zs || dgt > 0)
		outDgt(dgt);
}

void tfp_printf(const char *fmt, ...)
{
	va_list va;
	char *p;
	unsigned int i;
	char ch;

	va_start(va, fmt);

	while ((ch = *(fmt++))) {
		if (ch != '%') {
			putcharacter(ch);
		} else {
			char lz = 0;
			char w = 0;
			ch = *(fmt++);

			if (ch == '0') {
				ch = *(fmt++);
				lz = 1;
			}

			if (ch >= '0' && ch <= '9') {
				w = 0;
				while (ch >= '0' && ch <= '9') {
					w = (((w << 2) + w) << 1) + ch - '0';
					ch = *fmt++;
					}
			}

			bf = buf;
			p = bf;
			zs = 0;

			switch (ch) {
			case 0:
				goto abort;

			case 'u':
			case 'd':
				num = va_arg(va, unsigned int);
				if (ch == 'd' && (int) num < 0) {
					num = -(int)num;
					out('-');
				}

				for (i = 100000000; i != 1; i /= 10)
					divOut(i);

				outDgt(num);
				break;

			case 'p':
			case 'x':
			case 'X':
				uc = ch == 'X';
				num = va_arg(va, unsigned int);
				for (i = 0x10000000; i != 0x1; i >>= 4)
					divOut(i);

				outDgt(num);
				break;

			case 'c':
				out((char)(va_arg(va, int)));
				break;

			case 's':
				p = va_arg(va, char*);
				break;
			case '%':
				out('%');
				break;

			default:
				break;
				}

			*bf = 0;
			bf = p;
			while (*bf++ && w > 0)
				w--;

			while (w-- > 0)
				putcharacter(lz ? '0' : ' ');

			while ((ch = *p++))
				putcharacter(ch);
		}
	}

abort:
	putcharacter('\0');
	va_end(va);
}

#else

void min_printf(const char *fmt, ...)
{
	char ch;

	do {
		ch = *(fmt++);
		putcharacter(ch);
	} while (ch);
}

#endif /* CONFIG_CARL9170FW_PRINTF */
