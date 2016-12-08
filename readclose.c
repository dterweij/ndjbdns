/*
 * readclose.c: This file is part of the `djbdns' project, originally written
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

#include "error.h"
#include "readclose.h"

int
readclose_append (int fd, stralloc *sa, unsigned int bufsize)
{
    int r = 0;
    for (;;)
    {
        if (!stralloc_readyplus (sa, bufsize))
        {
            close (fd);
            return -1;
        }
        r = read (fd, sa->s + sa->len, bufsize);
        if (r == -1)
            if (errno == error_intr)
                continue;
        if (r <= 0)
        {
            close(fd);
            return r;
        }
        sa->len += r;
    }
}

int
readclose (int fd, stralloc *sa, unsigned int bufsize)
{
    if (!stralloc_copys (sa, ""))
    {
        close(fd);
        return -1;
    }

    return readclose_append (fd, sa, bufsize);
}
