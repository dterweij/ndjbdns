/*
 * alloc.c: This file is part of the `djbdns' project, originally written
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

#include <string.h>
#include <stdlib.h>

#include "alloc.h"
#include "error.h"

#define ALIGNMENT 16    /* XXX: assuming that this alignment is enough */
#define SPACE 2048      /* must be multiple of ALIGNMENT */

typedef union
{
    char irrelevant[ALIGNMENT];
    double d;
} aligned;

static aligned realspace[SPACE / ALIGNMENT];
#define space ((char *) realspace)
static unsigned int avail = SPACE; /* multiple of ALIGNMENT; 0<=avail<=SPACE */

/*@null@*//*@out@*/
char *
alloc (unsigned int n)
{
    char *x = 0;

    n = ALIGNMENT + n - (n & (ALIGNMENT - 1)); /* XXX: could overflow */
    if (n <= avail)
    {
        avail -= n;
        return space + avail;
    }

    if (!(x = malloc (n)))
        errno = error_nomem;
    else
        memset (x, 0, n);

    return x;
}

void
alloc_free(char *x)
{
    if (x >= space)
        if (x < space + SPACE)
            return;             /* XXX: assuming that pointers are flat */

    free (x);
}
