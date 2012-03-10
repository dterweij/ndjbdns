/*
 * dns_dfd.c: This file is part of the `djbdns' project, originally written
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

#include <stdio.h>

#include "dns.h"
#include "byte.h"
#include "error.h"
#include "alloc.h"

int
dns_domain_fromdot (char **out, const char *buf, unsigned int n)
{
    char ch = 0, *x = NULL;
    char label[63], name[255];

    unsigned int namelen = 0;       /* <= sizeof name */
    unsigned int labellen = 0;      /* <= sizeof label */

    errno = error_proto;

    for (;;)
    {
        if (!n)
            break;

        --n;
        ch = *buf++;
        if (ch == '.')
        {
            if (labellen)
            {
                if (namelen + labellen + 1 > sizeof name)
                    return 0;

                name[namelen++] = labellen;
                byte_copy (name + namelen, labellen, label);
                namelen += labellen;
                labellen = 0;
            }
            continue;
        }
        if (ch == '\\')
        {
            if (!n)
                break;

            --n;
            ch = *buf++;
            if ((ch >= '0') && (ch <= '7'))
            {
                ch -= '0';
                if (n && (*buf >= '0') && (*buf <= '7'))
                {
                    ch <<= 3;
                    ch += (*buf - '0');

                    --n;
                    ++buf;
                    if (n && (*buf >= '0') && (*buf <= '7'))
                    {
                        ch <<= 3;
                        ch += (*buf - '0');

                        --n;
                        ++buf;
                    }
                }
            }
        }
        if (labellen >= sizeof label)
            return 0;

        label[labellen++] = ch;
    }

    if (labellen)
    {
        if (namelen + labellen + 1 > sizeof name)
            return 0;

        name[namelen++] = labellen;
        byte_copy (name + namelen, labellen, label);
        namelen += labellen;
        labellen = 0;
    }

    if (namelen + 1 > sizeof name)
        return 0;
    name[namelen++] = 0;

    if (!(x = alloc (namelen)))
        return 0;
    byte_copy (x, namelen, name);

    if (*out)
        alloc_free (*out);
    *out = x;

    return 1;
}
