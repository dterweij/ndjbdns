/*
 * cdb_hash.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * Copyright (C) 2009 - 2013 Prasad J Pandit
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

#include "cdb.h"

uint32
cdb_hashadd (uint32 h, unsigned char c)
{
    h += (h << 5);
    return h ^ c;
}

uint32
cdb_hash (const char *buf, unsigned int len)
{
    uint32 h;

    h = CDB_HASHSTART;
    while (len)
    {
        h = cdb_hashadd (h, *buf++);
        --len;
    }

    return h;
}
