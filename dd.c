/*
 * dd.c: This file is part of the `djbdns' project, originally written
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

#include "dd.h"
#include "dns.h"

int
dd (const char *q, const char *base, char ip[4])
{
    int j = 0;
    unsigned int x = 0;

    for (j = 0; ; ++j)
    {
        if (dns_domain_equal (q, base))
            return j;
        if (j >= 4)
            return -1;

        if (*q <= 0)
            return -1;
        if (*q >= 4)
            return -1;
        if ((q[1] < '0') || (q[1] > '9'))
            return -1;

        x = q[1] - '0';
        if (*q == 1)
        {
            ip[j] = x;
            q += 2;
            continue;
        }
        if (!x)
            return -1;
        if ((q[2] < '0') || (q[2] > '9'))
            return -1;

        x = x * 10 + (q[2] - '0');
        if (*q == 2)
        {
            ip[j] = x;
            q += 3;
            continue;
        }
        if ((q[3] < '0') || (q[3] > '9'))
            return -1;

        x = x * 10 + (q[3] - '0');
        if (x > 255)
            return -1;
        ip[j] = x;
        q += 4;
    }
}
