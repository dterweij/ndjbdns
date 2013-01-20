/*
 * buffer.c: This file is part of the `djbdns' project, originally written
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


#include <err.h>
#include <unistd.h>

#include "str.h"
#include "byte.h"
#include "error.h"
#include "buffer.h"

char buffer_1_space[BUFFER_OUTSIZE];
static buffer it_1 = BUFFER_INIT (buffer_unixwrite, 1,
                                  buffer_1_space, sizeof (buffer_1_space));
buffer *buffer_1 = &it_1;


char buffer_2_space[256];
static buffer it_2 = BUFFER_INIT (buffer_unixwrite, 2,
                                  buffer_2_space, sizeof (buffer_2_space));
buffer *buffer_2 = &it_2;


static int
oneread (int (*op)(), int fd, char *buf, unsigned int len)
{
    int r = 0;

    for (;;)
    {
        r = op (fd, buf, len);
        if (r == -1)
            if (errno == error_intr)
                continue;

        return r;
    }
}

static int
getthis (buffer *s, char *buf, unsigned int len)
{
    if (len > s->p)
        len = s->p;

    s->p -= len;
    byte_copy (buf, len, s->x + s->n);
    s->n += len;

    return len;
}

static int
allwrite (int (*op)(), int fd, const char *buf, unsigned int len)
{
    int w = 0;

    while (len)
    {
        w = op (fd, buf, len);
        if (w == -1)
        {
            if (errno == error_intr)
                continue;

            return -1; /* note that some data may have been written */
        }
/*      if (w == 0)
            ;  luser's fault */
        buf += w;
        len -= w;
    }

    return 0;
}

void
buffer_init (buffer *s, int (*op)(), int fd, char *buf, unsigned int len)
{
    s->x = buf;
    s->fd = fd;
    s->op = op;
    s->p = 0;
    s->n = len;
}

int
buffer_feed (buffer *s)
{
    int r = 0;

    if (s->p)
        return s->p;

    r = oneread (s->op, s->fd, s->x, s->n);
    if (r <= 0)
        return r;

    s->p = r;
    s->n -= r;
    if (s->n > 0)
        byte_copyr (s->x + s->n, r, s->x);

    return r;
}

int
buffer_put (buffer *s, const char *buf, unsigned int len)
{
    unsigned int n = s->n;

    if (len > n - s->p)
    {
        if (buffer_flush (s) == -1)
            return -1;

        /* now s->p == 0 */
        if (n < BUFFER_OUTSIZE)
            n = BUFFER_OUTSIZE;
        while (len > s->n)
        {
            if (n > len)
                n = len;
            if (allwrite (s->op, s->fd, buf, n) == -1)
                return -1;

            buf += n;
            len -= n;
        }
    }

    /* now len <= s->n - s->p */
    byte_copy (s->x + s->p, len, buf);
    s->p += len;

    return 0;
}

int
buffer_copy (buffer *bout, buffer *bin)
{
    int n = 0;
    char *x = NULL;

    for (;;)
    {
        n = buffer_feed (bin);
        if (n < 0)
            return -2;
        if (!n)
            return 0;

        x = buffer_PEEK (bin);
        if (buffer_put (bout, x, n) == -1)
            return -3;

        buffer_SEEK (bin, n);
    }
}

int
buffer_bget (buffer *s, char *buf, unsigned int len)
{
    int r = 0;

    if (s->p > 0)
        return getthis (s, buf, len);
    if (s->n <= len)
        return oneread (s->op, s->fd, buf, s->n);

    r = buffer_feed (s);
    if (r <= 0)
        return r;

    return getthis (s, buf, len);
}

int
buffer_get (buffer *s, char *buf, unsigned int len)
{
    int r = 0;

    if (s->p > 0)
        return getthis (s, buf, len);
    if (s->n <= len)
        return oneread (s->op, s->fd, buf, len);

    r = buffer_feed (s);
    if (r <= 0)
        return r;

    return getthis (s, buf, len);
}

char *
buffer_peek (buffer *s)
{
    return s->x + s->n;
}

void
buffer_seek (buffer *s, unsigned int len)
{
    s->n += len;
    s->p -= len;
}

int
buffer_flush (buffer *s)
{
    int p = s->p;

    if (!p)
        return 0;

    s->p = 0;
    return allwrite (s->op, s->fd, s->x, p);
}

int
buffer_putalign (buffer *s, const char *buf, unsigned int len)
{
    unsigned int n = 0;

    while (len > (n = s->n - s->p))
    {
        byte_copy (s->x + s->p, n, buf);
        s->p += n;
        buf += n;
        len -= n;
        if (buffer_flush (s) == -1)
            return -1;
    }

    /* now len <= s->n - s->p */
    byte_copy (s->x + s->p, len, buf);
    s->p += len;

    return 0;
}

int
buffer_putflush (buffer *s, const char *buf, unsigned int len)
{
    if (buffer_flush (s) == -1)
        return -1;

    return allwrite (s->op, s->fd, buf, len);
}

int
buffer_putsalign (buffer *s, const char *buf)
{
    return buffer_putalign (s, buf, str_len (buf));
}

int
buffer_puts (buffer *s, const char *buf)
{
    return buffer_put (s, buf, str_len (buf));
}

int
buffer_putsflush (buffer *s, const char *buf)
{
    return buffer_putflush (s, buf, str_len (buf));
}

int
buffer_unixread (int fd, char *buf, unsigned int len)
{
    return read (fd, buf, len);
}

int
buffer_unixwrite (int fd, const char *buf, unsigned int len)
{
    return write (fd, buf, len);
}
