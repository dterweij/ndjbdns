/*
 * dns_domain.c: This file is part of the `djbdns' project, originally written
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


#include <assert.h>
#include <unistd.h>

#include "dns.h"
#include "case.h"
#include "byte.h"
#include "error.h"
#include "alloc.h"

unsigned int
dns_domain_length (const char *dn)
{
    const char *x = dn;
    unsigned char c = 0;

    if (x)
        while ((c = *x++))
            x += (unsigned int) c;

    return x - dn;
}

void
dns_domain_free (char **out)
{
    if (*out)
    {
        alloc_free (*out);
        *out = 0;
    }
}

int
dns_domain_copy (char **out, const char *in)
{
    char *x = NULL;
    unsigned int len = 0;

    assert (in != NULL);
    assert (out != NULL);

    len = dns_domain_length (in);
    if (!(x = alloc (len)))
        return 0;

    byte_copy (x, len, in);
    if (*out)
        alloc_free (*out);
    *out = x;

    return 1;
}

int
dns_domain_equal (const char *dn1, const char *dn2)
{
    unsigned int len = 0;

    len = dns_domain_length (dn1);
    if (len != dns_domain_length (dn2))
        return 0;
    if (case_diffb (dn1, len, dn2))
        return 0; /* safe since 63 < 'A' */

    return 1;
}

int
dns_domain_suffix (const char *big, const char *little)
{
    unsigned char c = 0;

    for (;;)
    {
        if (dns_domain_equal (big, little))
            return 1;
        if (!(c = *big++))
            return 0;

        big += c;
    }
}

unsigned int
dns_domain_suffixpos (const char *big, const char *little)
{
    unsigned char c = 0;
    const char *orig = big;

    for (;;)
    {
        if (dns_domain_equal (big, little))
            return big - orig;
        if (!(c = *big++))
            return 0;

        big += c;
    }
}
