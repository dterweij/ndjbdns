/*
 * rbldns.c: This file is part of the `ndjbdns' project, originally written
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

#include "dd.h"
#include "cdb.h"
#include "dns.h"
#include "env.h"
#include "ip4.h"
#include "str.h"
#include "byte.h"
#include "open.h"
#include "response.h"

static char *base;
static struct cdb c;
static char key[5];
static char data[100 + IP4_FMT];

static int
doit (char *q, char qtype[2])
{
    int i = 0, r = 0;
    int flaga = 0, flagtxt = 0;
    char ch, reverseip[4], ip[4];

    uint32 ipnum = 0, dlen = 0;

    flaga = byte_equal (qtype, 2, DNS_T_A);
    flagtxt = byte_equal (qtype, 2, DNS_T_TXT);
    if (byte_equal (qtype, 2, DNS_T_ANY))
        flaga = flagtxt = 1;
    if (!flaga && !flagtxt)
        goto REFUSE;
    if (dd (q, base, reverseip) != 4)
        goto REFUSE;

    uint32_unpack (reverseip, &ipnum);
    uint32_pack_big (ip, ipnum);

    for (i = 0; i <= 24; ++i)
    {
        ipnum >>= i;
        ipnum <<= i;
        uint32_pack_big (key, ipnum);
        key[4] = 32 - i;

        r = cdb_find (&c, key, 5);
        if (r == -1)
            return 0;
        if (r)
            break;
    }
    if (!r)
    {
        response_nxdomain ();
        return 1;
    }

    r = cdb_find (&c, "", 0);
    if (r == -1)
        return 0;
    if (r && ((dlen = cdb_datalen (&c)) >= 4))
    {
        if (dlen > 100)
            dlen = 100;
        if (cdb_read (&c, data, dlen, cdb_datapos (&c)) == -1)
            return 0;
    }
    else
    {
        dlen = 12;
        byte_copy (data, dlen, "\177\0\0\2Listed $");
    }

    if ((dlen >= 5) && (data[dlen - 1] == '$'))
    {
        --dlen;
        dlen += ip4_fmt (data + dlen, ip);
    }

    if (flaga)
    {
        if (!response_rstart (q, DNS_T_A, 2048))
            return 0;
        if (!response_addbytes (data, 4))
            return 0;
        response_rfinish (RESPONSE_ANSWER);
    }
    if (flagtxt)
    {
        if (!response_rstart (q, DNS_T_TXT, 2048))
            return 0;

        ch = dlen - 4;
        if (!response_addbytes (&ch, 1))
            return 0;
        if (!response_addbytes (data + 4, dlen - 4))
            return 0;
        response_rfinish (RESPONSE_ANSWER);
    }
    return 1;

REFUSE:
    response[2] &= ~4;
    response[3] &= ~15;
    response[3] |= 5;

    return 1;
}

int
respond (char *q, char qtype[2], char ip[4])
{
    int fd = 0;
    int result = 0;

    fd = open_read ("data.cdb");
    if (fd == -1)
        return 0;

    cdb_init (&c, fd);
    result = doit (q, qtype);
    cdb_free (&c);
    close (fd);

    return result;
}

void
initialize(void)
{
    char *x = NULL;

    x = env_get("BASE");
    if (!x)
        err (-1, "$BASE not set");
    if (!dns_domain_fromdot (&base, x, str_len (x)))
        err (-1, "unable to parse $BASE");
}
