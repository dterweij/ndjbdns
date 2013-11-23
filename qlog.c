/*
 * qlog.c: This file is part of the `djbdns' project, originally written
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

#include <time.h>

#include "qlog.h"
#include "buffer.h"
#include "common.h"

static void
put (char c)
{
    buffer_put (buffer_2, &c, 1);
}

/* static void
hex (unsigned char c)
{
    put ("0123456789abcdef"[(c >> 4) & 15]);
    put ("0123456789abcdef"[c & 15]);
} */

static void
octal (unsigned char c)
{
    put ('\\');
    put ('0' + ((c >> 6) & 7));
    put ('0' + ((c >> 3) & 7));
    put ('0' + (c & 7));
}

void
qlog (uint64 qnum, const char ip[4], uint16 port, const char id[2],
            const char *q, const char qtype[2], const char *result)
{
    char ch, ch2;
    time_t t = 0;
    char ltime[21];

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));

    string(ltime);
    put (' ');
    put ('Q');
    number (qnum);
    put (' ');

    number ((int)(ip[0] & 0xFF));
    put ('.');
    number ((int)(ip[1] & 0xFF));
    put ('.');
    number ((int)(ip[2] & 0xFF));
    put ('.');
    number ((int)(ip[3] & 0xFF));
    put (':');
    number (port);
    put (' ');

    logid(id);
    buffer_puts (buffer_2, result);
    logtype (qtype);
    put ('?');
    put (' ');

    if (!*q)
        put ('.');
    else
        while (1)
        {
            ch = *q++;
            while (ch--)
            {
                ch2 = *q++;
                if ((ch2 >= 'A') && (ch2 <= 'Z'))
                    ch2 += 32;
                if (((ch2 >= 'a') && (ch2 <= 'z'))
                    || ((ch2 >= '0') && (ch2 <= '9'))
                    || (ch2 == '-') || (ch2 == '_'))
                    put (ch2);
                else
                    octal (ch2);
            }
            if (!*q)
                break;
            put ('.');
    }

    put ('\n');
    buffer_flush (buffer_2);
}
