/*
 * pickdns.c: This file is part of the `djbdns' project, originally written
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


#include "dns.h"
#include "cdb.h"
#include "byte.h"
#include "case.h"
#include "open.h"
#include "common.h"
#include "response.h"

#define PIDFILE "/var/run/pickdns.pid"
#define LOGFILE "/var/log/pickdns.log"
#define CFGFILE SYSCONFDIR"/ndjbdns/pickdns.conf"

extern short mode;
enum op_mode { DAEMON = 1, DEBUG = 2 };

static struct cdb c;
static char key[258];
static char seed[128];
static char data[512];

void
initialize (void)
{
    read_conf (CFGFILE);

    if (mode & DAEMON)
    {
        /* redirect stdout & stderr to a log file */
        redirect_to_log (LOGFILE);

        write_pid (PIDFILE);
    }

    dns_random_init (seed);
}

static int
doit (char *q, char qtype[2], char ip[4])
{
    int r = 0;
    unsigned int dlen = 0;
    unsigned int qlen = 0;
    int flaga = 0, flagmx = 0;

    qlen = dns_domain_length (q);
    if (qlen > 255)
        return 0; /* impossible */

    flaga = byte_equal (qtype, 2, DNS_T_A);
    flagmx = byte_equal(qtype, 2, DNS_T_MX);
    if (byte_equal (qtype, 2, DNS_T_ANY))
        flaga = flagmx = 1;
    if (!flaga && !flagmx)
        goto REFUSE;

    key[0] = '%';
    byte_copy (key + 1, 4, ip);

    r = cdb_find (&c, key, 5);
    if (!r)
        r = cdb_find (&c, key, 4);
    if (!r)
        r = cdb_find (&c, key, 3);
    if (!r)
        r = cdb_find (&c, key, 2);
    if (r == -1)
        return 0;

    key[0] = '+';
    byte_zero (key + 1, 2);
    if (r && (cdb_datalen (&c) == 2))
        if (cdb_read (&c, key + 1, 2, cdb_datapos (&c)) == -1)
            return 0;

    byte_copy (key + 3, qlen, q);
    case_lowerb (key + 3, qlen + 3);

    r = cdb_find (&c, key, qlen + 3);
    if (!r)
    {
        byte_zero (key + 1, 2);
        r = cdb_find (&c, key, qlen + 3);
    }
    if (!r)
        goto REFUSE;
    if (r == -1)
        return 0;

    dlen = cdb_datalen (&c);
    if (dlen > 512)
        dlen = 512;
    if (cdb_read (&c, data, dlen, cdb_datapos (&c)) == -1)
        return 0;

    if (flaga)
    {
        dns_sortip (data, dlen);
        if (dlen > 12)
            dlen = 12;
        while (dlen >= 4)
        {
            dlen -= 4;
            if (!response_rstart (q, DNS_T_A, 5))
                return 0;
            if (!response_addbytes (data + dlen, 4))
                return 0;
            response_rfinish (RESPONSE_ANSWER);
        }
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
    int fd;
    int result;

    fd = open_read ("data.cdb");
    if (fd == -1)
        return 0;

    cdb_init (&c, fd);
    result = doit (q, qtype, ip);
    cdb_free (&c);

    close (fd);
    return result;
}
