/*
 * fmt_ulong.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * Copyright (C) 2009 - 2012 Prasad J Pandit
 *
 * This program is a free software; you can redistribute it and/or modify
 * it under the terms of GNU General Public License as published by Free
 * Software Foundation; either version 2 of the license or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * of FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include "fmt.h"

unsigned int
fmt_ulong (register char *s, register unsigned long u)
{
    register unsigned long q = u;
    register unsigned int len = 1;

    while (q > 9)
    {
        ++len;
        q /= 10;
    }
    if (s)
    {
        s += len;
        do
        {
            *--s = '0' + (u % 10);
            u /= 10;
        } while (u); /* handles u == 0 */
    }

    return len;
}
