/*
 * log.c: This file is part of the `djbdns' project, originally written
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

#include "log.h"
#include "byte.h"
#include "error.h"
#include "buffer.h"
#include "uint16.h"
#include "uint32.h"
#include "uint64.h"

static void
hex (unsigned char c)
{
    buffer_put (buffer_2, "0123456789abcdef" + (c >> 4), 1);
    buffer_put (buffer_2, "0123456789abcdef" + (c & 15), 1);
}

static void
number (uint64 u64)
{
    char buf[20];
    unsigned int pos = 0;

    pos = sizeof (buf);
    do
    {
        if (!pos)
            break;
        buf[--pos] = '0' + (u64 % 10);
        u64 /= 10;
    } while (u64);

    buffer_put (buffer_2, buf + pos, sizeof (buf) - pos);
}

static void
string (const char *s)
{
    buffer_puts (buffer_2, s);
}

static void
line (void)
{
    string ("\n");
    buffer_flush (buffer_2);
}

static void
space (void)
{
    string (" ");
}

static void
ip (const char i[4])
{
    number ((int)(i[0] & 0xFF));
    string (".");
    number ((int)(i[1] & 0xFF));
    string (".");
    number ((int)(i[2] & 0xFF));
    string (".");
    number ((int)(i[3] & 0xFF));
}

static void
logid (const char id[2])
{
    uint16 u = 0;
    uint16_unpack_big (id, &u);

    number (u);
}

static void
logtype (const char type[2])
{
    uint16 u = 0;
    char *qtype[] = {
        "\0",
        "A",        /* 1 a host address */
        "NS",       /* 2 an authoritative name server */
        "MD",       /* 3 a mail destination (obsolete, use MX) */
        "MF",       /* 4 a mail forwarder (obsolete, use MX) */
        "CNAME",    /* 5 the canonical name for an alias */
        "SOA",      /* 6 marks the start of a zone authority */
        "MB",       /* 7 a mailbox domain name (experimental) */
        "MG",       /* 8 a mail group member (experimental) */
        "MR",       /* 9 a mail rename domain name (experimental) */
        "NULL",     /*10 a NULL RR (experimental) */
        "WKS",      /*11 a well known service description */
        "PTR",      /*12 a domain name pointer */
        "HINFO",    /*13 host information */
        "MINFO",    /*14 mailbox or mail list information */
        "MX",       /*15 mail exchange */
        "TXT",      /*16 text strings */
        "AAAA",     /*17  28 IPv6 host address */
        "AXFR",     /*18 252 transfer of an entire zone */
        "MAILB",    /*19 253 mailbox-related records MB, MG or MR */
        "MAILA",    /*20 254 mail agent RRs (obsolete, use MX) */
        "*",        /*21 255 requst for all records*/
    };

    uint16_unpack_big (type, &u);
    u = (u < 17) ? u : (u == 28) ? 17 : (u > 251 && u < 256) ? u - 234 : u;
    if (u < (sizeof (qtype) / sizeof (char *)))
        string(qtype[u]);
    else
        number (u);
}

static void
name (const char *q)
{
    char ch = 0;
    int state = 0;

    if (!*q)
    {
        string (".");
        return;
    }
    while ((state = *q++))
    {
        while (state)
        {
            ch = *q++;
            --state;
            if ((ch <= 32) || (ch > 126))
                ch = '?';
            if ((ch >= 'A') && (ch <= 'Z'))
                ch += 32;
            buffer_put (buffer_2, &ch, 1);
        }
        string (".");
    }
}

void
log_query (uint64 qnum, const char client[4], unsigned int port,
                    const char id[2], const char *q, const char qtype[2])
{
    time_t t = 0;
    char ltime[21];

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));

    string(ltime);
    space();
    string ("Q");
    number (qnum);
    space ();

    ip (client);
    string (":");
    number (port);

    space();
    logid(id);
    space ();

    logtype (qtype);
    string("?");
    space ();
    name (q);

    line ();
}

void
log_querydone (uint64 qnum, const char *resp, unsigned int len)
{
    time_t t = 0;
    uint16_t ancount = 0;
    char ltime[21], r = *(resp + 3) & 0x0F;

    char *rcode[] = {
        ":success",
        ":format error",
        ":server failure",
        ":name error",
        ":not implemented",
        ":request refused",
    };

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));
    string(ltime);

    space();
    string ("R");
    number (qnum);
    space ();
    number (r);
    string (rcode[(int)r]);
    space ();
    uint16_unpack_big (resp + 6, &ancount);
    number (ancount);
    space ();
    number (len);
    line ();
}

void
log_querydrop (uint64 qnum)
{
    time_t t = 0;
    char ltime[21];
    const char *x = error_str (errno);

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));
    string(ltime);

    space();
    string ("drop Q");
    number (qnum);
    space ();
    string (x);

    line ();
}

void
log_tcpopen (const char client[4], unsigned int port)
{
    time_t t = 0;
    char ltime[21];

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));
    string(ltime);

    string (" tcpopen ");
    ip (client);
    string (":");
    number (port);

    line ();
}

void
log_tcpclose (const char client[4], unsigned int port)
{
    time_t t = 0;
    char ltime[21];
    const char *x = error_str (errno);

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));
    string(ltime);

    string (" tcpclose ");
    ip (client);
    string (":");
    number (port);
    space ();
    string (x);

    line();
}

void
log_tx (const char *q, const char qtype[2], const char *control,
                    const char servers[64], unsigned int gluelessness)
{
    int i = 0;

    string (" + tx ");
    number (gluelessness);
    space ();
    logtype (qtype);
    space ();
    name (q);
    space ();
    name (control);
    for (i = 0; i < 64; i += 4)
    {
        if (byte_diff (servers + i, 4, "\0\0\0\0"))
        {
            space ();
            ip (servers + i);
        }
    }

    line ();
}

void
log_merge (const char *addr, const char qtype[2], const char *q)
{
    string (" + merge ");
    ip(addr);
    space();
    logtype(qtype);
    space ();
    name (q);
    line ();
}

void
log_cachedanswer (const char *q, const char type[2])
{
    string ("     cc ");
    logtype (type);
    space ();
    name (q);

    line ();
}

void
log_cachedcname (const char *dn, const char *dn2)
{
    string("     cc cname ");
    name (dn);
    space ();
    name (dn2);

    line();
}

void
log_cachedns (const char *control, const char *ns)
{
    string ("     cc ns ");
    name (control);
    space ();
    name (ns);

    line();
}

void
log_cachednxdomain (const char *dn)
{
    string ("     cc nxdomain ");
    name (dn);

    line ();
}

void
log_nxdomain (const char server[4], const char *q, unsigned int ttl)
{
    string ("     nxdomain ");
    ip (server);
    space ();
    number (ttl);
    space ();
    name (q);

    line ();
}

void
log_nodata (const char server[4], const char *q,
                       const char qtype[2], unsigned int ttl)
{
    string ("     nodata ");
    ip (server);
    space ();
    number (ttl);
    space ();
    logtype (qtype);
    space ();
    name (q);

    line();
}

void
log_lame (const char server[4], const char *control, const char *referral)
{
    string ("     lame ");
    ip (server);
    space ();
    name (control);
    space ();
    name (referral);

    line();
}

void log_servfail (const char *dn)
{
    time_t t = 0;
    char ltime[21];
    const char *x = error_str (errno);

    time(&t);
    strftime (ltime, sizeof (ltime), "%b %d %Y %T", localtime (&t));
    string(ltime);

    string (" servfail ");
    name (dn);
    space ();
    string (x);

    line ();
}

void
log_rr (const char server[4], const char *q, const char type[2],
                   const char *buf, unsigned int len, unsigned int ttl)
{
    int i = 0;

    string ("     rr ");
    ip (server);
    space ();
    number (ttl);
    space ();
    logtype (type);
    space ();
    name (q);
    space ();

    for (i = 0; (unsigned)i < len; ++i)
    {
        hex (buf[i]);
        if (i > 30)
        {
            string ("...");
            break;
        }
    }

    line ();
}

void
log_rrns (const char server[4], const char *q,
                     const char *data, unsigned int ttl)
{
    string ("     rr ");
    ip (server);
    space ();
    number (ttl);
    string (" ns ");
    name (q);
    space ();
    name (data);

    line ();
}

void
log_rrcname (const char server[4], const char *q,
                        const char *data, unsigned int ttl)
{
    string ("     rr ");
    ip (server);
    space ();
    number (ttl);
    string (" cname ");
    name (q);
    space ();
    name (data);

    line ();
}

void
log_rrptr (const char server[4], const char *q,
                      const char *data, unsigned int ttl)
{
    string ("     rr ");
    ip (server);
    space ();
    number (ttl);
    string (" ptr ");
    name (q);
    space ();
    name (data);

    line ();
}

void
log_rrmx (const char server[4], const char *q,
                     const char *mx, const char pref[2],unsigned int ttl)
{
    uint16 u = 0;

    string ("     rr ");
    ip (server);
    space ();
    number (ttl);
    string (" mx ");
    name (q);
    space ();
    uint16_unpack_big (pref, &u);
    number (u);
    space ();
    name (mx);

    line();
}

void
log_rrsoa (const char server[4], const char *q, const char *n1,
                    const char *n2, const char misc[20], unsigned int ttl)
{
    int i = 0;
    uint32 u = 0;

    string ("     rr ");
    ip (server);
    space ();
    number (ttl);
    string (" soa ");
    name (q);
    space ();
    name (n1);
    space ();
    name (n2);
    for (i = 0; i < 20; i += 4)
    {
        uint32_unpack_big (misc + i, &u);
        space ();
        number (u);
    }

    line ();
}

void
log_stats (int uactive, int tactive, uint64 numqueries, uint64 cache_motion)
{

    string ("   = ss Q");
    number (numqueries);
    string (" Csize ");
    number (cache_motion);
    string (" Qudp ");
    number (uactive);
    string (" Qtcp ");
    number (tactive);

    line ();
}
