/*
 * str_chr.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * I've modified this file for good and am releasing this new version under
 * GNU General Public License.
 * Copyright (C) 2009 - 2011 Prasad J Pandit
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

#include "str.h"

unsigned int
str_chr (register const char *s, int c)
{
    register char ch = c;
    register const char *t = s;

    while (t)
    {
        if (*t == '\0' || *t == ch)
            break;
        ++t;

        if (*t == '\0' || *t == ch)
            break;
        ++t;

        if (*t == '\0' || *t == ch)
            break;
        ++t;

        if (*t == '\0' || *t == ch)
            break;
        ++t;
    }

    return t - s;
}
