/*
 * ip4_fmt.c: This file is part of the `djbdns' project, originally written
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
#include "ip4.h"

unsigned int
ip4_fmt (char *s, const char ip[4])
{
    unsigned int i = 0, len = 0;

    i = fmt_ulong (s, (unsigned long)(unsigned char)ip[0]);
    len += i;
    if (s)
        s += i;
    if (s)
        *s++ = '.';
    ++len;

    i = fmt_ulong (s, (unsigned long)(unsigned char)ip[1]);
    len += i;
    if (s)
        s += i;
    if (s)
        *s++ = '.';
    ++len;

    i = fmt_ulong (s, (unsigned long)(unsigned char)ip[2]);
    len += i;
    if (s)
        s += i;
    if (s)
        *s++ = '.';
    ++len;

    i = fmt_ulong (s, (unsigned long)(unsigned char)ip[3]);
    len += i;
    if (s)
        s += i;

    return len;
}
