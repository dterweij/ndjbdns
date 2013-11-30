/*
 * cdb.c: This file is part of the `djbdns' project, originally written
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

#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "cdb.h"
#include "seek.h"
#include "byte.h"
#include "error.h"

void
cdb_free (struct cdb *c)
{
    if (c->map)
    {
        munmap (c->map, c->size);
        c->map = 0;
    }
}

/*
void __inline__
cdb_findstart (struct cdb *c)
{
    c->loop = 0;
}
*/

void
cdb_init (struct cdb *c, int fd)
{
    char *x;
    struct stat st;

    cdb_free (c);
    cdb_findstart (c);
    c->fd = fd;

    if ((fstat (fd, &st) == 0) && (st.st_size <= 0xffffffff))
    {
        x = mmap (0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (x + 1)
        {
            c->size = st.st_size;
            c->map = x;
        }
    }
}

int
cdb_read (struct cdb *c, char *buf, unsigned int len, uint32 pos)
{
    if (c->map)
    {
        if ((pos > c->size) || (c->size - pos < len))
            goto FORMAT;
        byte_copy (buf, len, c->map + pos);
    }
    else
    {
        if (seek_set (c->fd, pos) == -1)
            return -1;

        while (len > 0)
        {
            int r;
            do
                r = read (c->fd, buf, len);
            while ((r == -1) && (errno == error_intr));

            if (r == -1)
                return -1;
            if (r == 0)
                goto FORMAT;
            buf += r;
            len -= r;
        }
    }
    return 0;

FORMAT:
    errno = error_proto;
    return -1;
}

static int
match (struct cdb *c, const char *key, unsigned int len, uint32 pos)
{
    int n;
    char buf[32];

    while (len > 0)
    {
        n = sizeof buf;
        if ((unsigned)n > len)
            n = len;
        if (cdb_read (c, buf, n, pos) == -1)
            return -1;
        if (byte_diff (buf, n, key))
            return 0;
        pos += n;
        key += n;
        len -= n;
    }

    return 1;
}

int
cdb_findnext (struct cdb *c, const char *key, unsigned int len)
{
    uint32 u;
    uint32 pos;
    char buf[8];

    if (!c->loop)
    {
        u = cdb_hash (key, len);
        if (cdb_read (c, buf, 8, (u << 3) & 2047) == -1)
            return -1;

        uint32_unpack (buf + 4, &c->hslots);
        if (!c->hslots)
            return 0;

        uint32_unpack (buf, &c->hpos);
        c->khash = u;
        u >>= 8;
        u %= c->hslots;
        u <<= 3;
        c->kpos = c->hpos + u;
    }

    while (c->loop < c->hslots)
    {
        if (cdb_read (c, buf, 8, c->kpos) == -1)
            return -1;

        uint32_unpack (buf + 4, &pos);
        if (!pos)
            return 0;

        c->loop += 1;
        c->kpos += 8;
        if (c->kpos == c->hpos + (c->hslots << 3))
            c->kpos = c->hpos;

        uint32_unpack (buf, &u);
        if (u == c->khash)
        {
            if (cdb_read (c, buf, 8, pos) == -1)
                return -1;

            uint32_unpack (buf, &u);
            if (u == len)
            {
                switch (match (c, key, len, pos + 8))
                {
                case -1:
                    return -1;

                case 1:
                    uint32_unpack (buf + 4, &c->dlen);
                    c->dpos = pos + 8 + len;
                    return 1;
                }
            }
        }
    }

    return 0;
}

int
cdb_find (struct cdb *c, const char *key, unsigned int len)
{
    cdb_findstart (c);
    return cdb_findnext (c, key, len);
}
