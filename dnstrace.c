/*
 * dnstrace.c: This file is part of the `djbdns' project, originally written
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "version.h"

#include "fmt.h"
#include "str.h"
#include "byte.h"
#include "ip4.h"
#include "uint16.h"
#include "uint32.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "buffer.h"
#include "stralloc.h"
#include "error.h"
#include "strerr.h"
#include "iopause.h"
#include "printrecord.h"
#include "alloc.h"
#include "parsetype.h"
#include "dd.h"
#include "dns.h"


short mode = 0;
static char *prog = NULL;

char ipstr[IP4_FMT];
static stralloc tmp;
static stralloc querystr;
static struct dns_transmit tx;


void
usage (void)
{
    printf ("Usage: %s <type> <name> <root-ip> [<root-ip> ...]\n", prog);
}


void
printh (void)
{
    usage ();
    printf ("\n Options:\n");
    printf ("%-17s %s\n", "    -h --help", "print this help");
    printf ("%-17s %s\n", "    -v --version", "print version information");
    printf ("\nReport bugs to <pj.pandit@yahoo.co.in>\n");
}


int
check_option (int argc, char *argv[])
{
    int n = 0, ind = 0;
    const char optstr[] = "+:hv";
    struct option lopt[] = \
    {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'v' },
        { 0, 0, 0, 0 }
    };

    opterr = optind = 0;
    while ((n = getopt_long (argc, argv, optstr, lopt, &ind)) != -1)
    {
        switch (n)
        {
        case 'h':
            printh ();
            exit (0);

        case 'v':
            printf ("%s is part of djbdns version %s\n", prog, VERSION);
            exit (0);

        default:
            errx (-1, "unknown option `%c', see: --help", optopt);
        }
    }

    return optind;
}


void
printdomain (const char *d)
{
    if (!stralloc_copys (&tmp, ""))
        err (-1, "could not allocate enough memory");
    if (!dns_domain_todot_cat (&tmp, d))
        err (-1, "could not allocate enough memory");

    buffer_put (buffer_1, tmp.s, tmp.len);
}


int
resolve (char *q, char qtype[2], char ip[4])
{
    struct taia start;
    struct taia stamp;
    struct taia deadline;

    int r;
    char servers[64];
    iopause_fd x[1];

    taia_now (&start);

    byte_zero (servers, 64);
    byte_copy (servers, 4, ip);

    if (dns_transmit_start (&tx, servers, 0, q, qtype, "\0\0\0\0") == -1)
        return -1;

    for (;;)
    {
        taia_now (&stamp);
        taia_uint (&deadline, 120);
        taia_add (&deadline, &deadline, &stamp);

        dns_transmit_io (&tx, x, &deadline);
        iopause (x, 1, &deadline, &stamp);
        r = dns_transmit_get (&tx, x, &stamp);

        if (r == -1)
            return -1;
        if (r == 1)
            break;
    }

    taia_now (&stamp);
    taia_sub (&stamp, &stamp, &start);
    taia_uint (&deadline, 1);
    if (taia_less (&deadline, &stamp))
    {
        buffer_put (buffer_1, querystr.s, querystr.len);
        buffer_puts (buffer_1, "Alert: took more than 1 second\n");
    }

    return 0;
}


struct address
{
    char *owner;
    char ip[4];
};

GEN_ALLOC_typedef (address_alloc, struct address, s, len, a)
GEN_ALLOC_readyplus (address_alloc, struct address, s, len,
                                    a, i, n, x, 30, address_alloc_readyplus)
GEN_ALLOC_append (address_alloc, struct address, s, len, a, i,
                    n, x, 30, address_alloc_readyplus, address_alloc_append)

static address_alloc address;

struct ns
{
    char *owner;
    char *ns;
};

GEN_ALLOC_typedef (ns_alloc, struct ns, s, len, a)
GEN_ALLOC_readyplus (ns_alloc, struct ns, s, len, a, i, n,
                                                  x, 30, ns_alloc_readyplus)
GEN_ALLOC_append (ns_alloc, struct ns, s, len, a, i,
                            n, x, 30, ns_alloc_readyplus, ns_alloc_append)

static ns_alloc ns;

struct query
{
    char *owner;
    char type[2];
};

GEN_ALLOC_typedef (query_alloc, struct query, s, len, a)
GEN_ALLOC_readyplus (query_alloc, struct query, s, len,
                                  a, i, n, x, 30, query_alloc_readyplus)
GEN_ALLOC_append (query_alloc, struct query, s, len, a, i,
                      n, x, 30, query_alloc_readyplus, query_alloc_append)

static query_alloc query;

struct qt
{
    char *owner;
    char type[2];
    char *control;
    char ip[4];
};

GEN_ALLOC_typedef (qt_alloc, struct qt, s, len, a)
GEN_ALLOC_readyplus (qt_alloc, struct qt, s, len, a, i,
                                             n, x, 30, qt_alloc_readyplus)
GEN_ALLOC_append (qt_alloc, struct qt, s, len, a, i,
                            n, x, 30, qt_alloc_readyplus, qt_alloc_append)

static qt_alloc qt;


void
qt_add (const char *q, const char type[2],
                       const char *control, const char ip[4])
{
    int i = 0;
    struct qt x;

    if (!*q)
        return; /* don't ask the roots about our artificial . host */

    for (i = 0; i < qt.len; i++)
    {
        if (dns_domain_equal (qt.s[i].owner, q))
            if (dns_domain_equal (qt.s[i].control, control))
                if (byte_equal (qt.s[i].type, 2, type))
                    if (byte_equal (qt.s[i].ip, 4, ip))
                        return;
    }

    byte_zero (&x, sizeof x);
    if (!dns_domain_copy (&x.owner, q))
        err (-1, "could not allocate enough memory");
    if (!dns_domain_copy (&x.control, control))
        err (-1, "could not allocate enough memory");

    byte_copy (x.type, 2, type);
    byte_copy (x.ip, 4, ip);
    if (!qt_alloc_append (&qt, &x))
        err (-1, "could not allocate enough memory");
}


void
query_add (const char *owner, const char type[2])
{
    struct query x;
    int i = 0, j = 0;

    for (i = 0; i < query.len; i++)
    {
        if (dns_domain_equal (query.s[i].owner, owner))
        {
            if (byte_equal (query.s[i].type, 2, type))
                return;
        }
    }

    byte_zero(&x, sizeof x);
    if (!dns_domain_copy (&x.owner, owner))
        err (-1, "could not allocate enough memory");
    byte_copy (x.type, 2, type);
    if (!query_alloc_append (&query, &x))
        err (-1, "could not allocate enough memory");

    for (i = 0; i < ns.len; i++)
    {
        if (dns_domain_suffix (owner, ns.s[i].owner))
        {
            for (j = 0; j < address.len; j++)
            {
                if (dns_domain_equal (ns.s[i].ns, address.s[j].owner))
                    qt_add (owner, type, ns.s[i].owner, address.s[j].ip);
            }
        }
    }
}


void
ns_add (const char *owner, const char *server)
{
    struct ns x;
    int i = 0, j = 0;

    buffer_put (buffer_1, querystr.s, querystr.len);
    buffer_puts (buffer_1, "NS:");
    printdomain (owner);
    buffer_puts (buffer_1, ":");
    printdomain (server);
    buffer_puts (buffer_1, "\n");

    for (i = 0; i < ns.len; i++)
    {
        if (dns_domain_equal (ns.s[i].owner, owner))
        {
            if (dns_domain_equal (ns.s[i].ns, server))
                return;
        }
    }

    query_add (server, DNS_T_A);

    byte_zero (&x, sizeof x);
    if (!dns_domain_copy (&x.owner, owner))
        err (-1, "could not allocate enough memory");
    if (!dns_domain_copy (&x.ns, server))
        err (-1, "could not allocate enough memory");
    if (!ns_alloc_append (&ns, &x))
        err (-1, "could not allocate enough memory");

    for (i = 0; i < query.len; i++)
    {
        if (dns_domain_suffix (query.s[i].owner, owner))
        {
            for (j = 0; j < address.len; j++)
            {
                if (dns_domain_equal (server, address.s[j].owner))
                    qt_add (query.s[i].owner, query.s[i].type,
                                              owner, address.s[j].ip);
            }
        }
    }
}


void
address_add (const char *owner, const char ip[4])
{
    int i = 0, j = 0;
    struct address x;

    buffer_put (buffer_1, querystr.s, querystr.len);
    buffer_puts (buffer_1, "A:");
    printdomain (owner);
    buffer_puts (buffer_1, ":");
    buffer_put (buffer_1, ipstr, ip4_fmt (ipstr, ip));
    buffer_puts (buffer_1, "\n");

    for (i = 0; i < address.len; ++i)
    {
        if (dns_domain_equal (address.s[i].owner, owner))
        {
            if (byte_equal (address.s[i].ip, 4, ip))
                return;
        }
    }

    byte_zero (&x, sizeof x);
    if (!dns_domain_copy (&x.owner, owner))
        err (-1, "could not allocate enough memory");
    byte_copy (x.ip, 4, ip);
    if (!address_alloc_append (&address, &x))
        err (-1, "could not allocate enough memory");

    if (dns_domain_equal (ns.s[i].ns, owner))
    {
        for (j = 0; j < query.len; ++j)
        {
            if (dns_domain_suffix (query.s[j].owner, ns.s[i].owner))
                qt_add (query.s[j].owner, query.s[j].type, ns.s[i].owner, ip);
        }
    }
}


char seed[128];

static char *t1 = NULL;
static char *t2 = NULL;
static char *referral = NULL;
static char *cname = NULL;


static int
typematch (const char rtype[2], const char qtype[2])
{
    return byte_equal (qtype, 2, rtype) || byte_equal (qtype, 2, DNS_T_ANY);
}

void
parsepacket (const char *buf, unsigned int len, const char *d,
                              const char dtype[2], const char *control)
{
    char misc[20];
    char header[12];

    unsigned int pos = 0;
    uint16 numanswers = 0;
    unsigned int posanswers = 0;

    uint16 numauthority = 0;
    unsigned int posauthority = 0;

    uint16 numglue = 0;
    unsigned int posglue = 0;

    uint16 datalen = 0;
    unsigned int rcode = 0;

    int j = 0;
    const char *x = NULL;

    int flagout = 0, flagcname = 0;
    int flagreferral = 0, flagsoa = 0;

    pos = dns_packet_copy (buf, len, 0, header, 12);
    if (!pos)
        goto DIE;
    pos = dns_packet_skipname (buf, len, pos);
    if (!pos)
        goto DIE;
    pos += 4;

    uint16_unpack_big (header + 6, &numanswers);
    uint16_unpack_big (header + 8, &numauthority);
    uint16_unpack_big (header + 10, &numglue);

    rcode = header[3] & 15;
    if (rcode && (rcode != 3))
    {
        errno = error_proto;
        goto DIE;
    } /* impossible */

    posanswers = pos;
    for (j = 0; j < numanswers; ++j)
    {
        pos = dns_packet_getname (buf, len, pos, &t1);
        if (!pos)
            goto DIE;
        pos = dns_packet_copy (buf, len, pos, header, 10);
        if (!pos)
            goto DIE;

        if (dns_domain_equal (t1, d))
        {
            if (byte_equal (header + 2, 2, DNS_C_IN))
            {
                if (typematch (header, dtype))
                    flagout = 1;
                else if (typematch (header, DNS_T_CNAME))
                {
                    if (!dns_packet_getname (buf, len, pos, &cname))
                        goto DIE;
                    flagcname = 1;
                }
            }
        }
        uint16_unpack_big (header + 8, &datalen);
        pos += datalen;
    }

    posauthority = pos;
    for (j = 0; j < numauthority; ++j)
    {
        pos = dns_packet_getname (buf, len, pos, &t1);
        if (!pos)
            goto DIE;
        pos = dns_packet_copy (buf, len, pos, header, 10);
        if (!pos)
            goto DIE;
        if (typematch (header, DNS_T_SOA))
          flagsoa = 1;
        else if (typematch (header, DNS_T_NS))
        {
            flagreferral = 1;
            if (!dns_domain_copy (&referral, t1))
                goto DIE;
        }
        uint16_unpack_big (header + 8, &datalen);
        pos += datalen;
    }
    posglue = pos;

    if (!flagcname && !rcode && !flagout && flagreferral && !flagsoa)
    {
        if (dns_domain_equal (referral, control)
            || !dns_domain_suffix (referral, control))
        {
            buffer_put (buffer_1, querystr.s, querystr.len);
            buffer_puts (buffer_1, "ALERT:lame server; refers to ");
            printdomain (referral);
            buffer_puts (buffer_1, "\n");
            return;
        }
    }

    pos = posanswers;
    for (j = 0; j < numanswers + numauthority + numglue; ++j)
    {
        pos = dns_packet_getname (buf, len, pos, &t1);
        if (!pos)
            goto DIE;
        pos = dns_packet_copy (buf, len, pos, header, 10);
        if (!pos)
            goto DIE;

        uint16_unpack_big (header + 8, &datalen);
        if (dns_domain_suffix (t1, control))
        {
            if (byte_equal (header + 2, 2, DNS_C_IN))
            {
                if (typematch (header, DNS_T_NS))
                {
                    if (!dns_packet_getname (buf, len, pos, &t2))
                        goto DIE;

                    ns_add (t1, t2);
                }
                else if (typematch (header, DNS_T_A) && datalen == 4)
                {
                    if (!dns_packet_copy (buf, len, pos, misc, 4))
                        goto DIE;

                    address_add (t1, misc);
                }
            }
        }
        pos += datalen;
    }

    if (flagcname)
    {
        query_add (cname, dtype);
        buffer_put (buffer_1, querystr.s, querystr.len);
        buffer_puts (buffer_1, "CNAME:");
        printdomain (cname);
        buffer_puts (buffer_1, "\n");

        return;
    }
    if (rcode == 3)
    {
        buffer_put (buffer_1, querystr.s, querystr.len);
        buffer_puts (buffer_1, "NXDOMAIN\n");

        return;
    }
    if (flagout || flagsoa || !flagreferral)
    {
        if (!flagout)
        {
            buffer_put (buffer_1, querystr.s, querystr.len);
            buffer_puts (buffer_1, "NODATA\n");

            return;
        }
        pos = posanswers;
        for (j = 0; j < numanswers + numauthority + numglue; ++j)
        {
            pos = printrecord (&tmp, buf, len, pos, d, dtype);
            if (!pos)
                goto DIE;
            if (tmp.len)
            {
                buffer_put (buffer_1, querystr.s, querystr.len);
                buffer_puts (buffer_1, "answer:");
                buffer_put (buffer_1, tmp.s, tmp.len); /* includes \n */
            }
        }

        return;
    }

    if (!dns_domain_suffix (d, referral))
        goto DIE;

    buffer_put (buffer_1, querystr.s, querystr.len);
    buffer_puts (buffer_1, "see:");
    printdomain (referral);
    buffer_puts (buffer_1, "\n");

    return;

DIE:
    x = error_str (errno);
    buffer_put (buffer_1, querystr.s, querystr.len);
    buffer_puts (buffer_1, "ALERT:unable to parse response packet; ");
    buffer_puts (buffer_1, x);
    buffer_puts (buffer_1, "\n");
}


int
main (int argc, char *argv[])
{
    static stralloc out;
    static stralloc udn;
    static stralloc fqdn;
    static char *q = NULL;

    int i = 0;
    uint16 u16 = 0;

    char ip[64];
    char type[2];
    char *control = NULL;

    prog = strdup ((q = strrchr (argv[0], '/')) != NULL ?  q + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;

    if (argc < 3)
    {
        usage ();
        return 0;
    }

    dns_random_init (seed);
    if (!stralloc_copys (&querystr, "0:.:.:start:"))
        err (-1, "could not allocate enough memory");
    if (!address_alloc_readyplus (&address, 1))
        err (-1, "could not allocate enough memory");
    if (!query_alloc_readyplus (&query, 1))
        err (-1, "could not allocate enough memory");
    if (!ns_alloc_readyplus (&ns, 1))
        err (-1, "could not allocate enough memory");
    if (!qt_alloc_readyplus (&qt, 1))
        err (-1, "could not allocate enough memory");

    if (!parsetype (*argv, type))
        usage ();
    argv++;

    q = NULL;
    if (!dns_domain_fromdot (&q, *argv, str_len (*argv)))
        err (-1, "could not allocate enough memory");
    argv++;

    query_add (q, type);
    ns_add ("", "");

    while (*argv)
    {
        if (!stralloc_copys (&udn, *argv))
            err (-1, "could not allocate enough memory");
        if (dns_ip4_qualify (&out, &fqdn, &udn) == -1)
            err (-1, "could not allocate enough memory");
        for (i = 0; i + 4 <= out.len; i += 4)
          address_add ("", out.s + i);

        argv++;
    }

    for (i = 0; i < qt.len; ++i)
    {
        if (!dns_domain_copy (&q, qt.s[i].owner))
            err (-1, "could not allocate enough memory");

        control = qt.s[i].control;
        if (!dns_domain_suffix (q, control))
            continue;

        byte_copy (type, 2, qt.s[i].type);
        byte_copy (ip, 4, qt.s[i].ip);

        if (!stralloc_copys (&querystr, ""))
            err (-1, "could not allocate enough memory");

        uint16_unpack_big (type, &u16);
        if (!stralloc_catulong0 (&querystr, u16, 0))
            err (-1, "could not allocate enough memory");
        if (!stralloc_cats (&querystr, ":"))
            err (-1, "could not allocate enough memory");
        if (!dns_domain_todot_cat (&querystr, q))
            err (-1, "could not allocate enough memory");
        if (!stralloc_cats (&querystr, ":"))
            err (-1, "could not allocate enough memory");
        if (!dns_domain_todot_cat (&querystr, control))
            err (-1, "could not allocate enough memory");
        if (!stralloc_cats(&querystr,":"))
            err (-1, "could not allocate enough memory");
        if (!stralloc_catb (&querystr, ipstr, ip4_fmt (ipstr, ip)))
            err (-1, "could not allocate enough memory");
        if (!stralloc_cats (&querystr, ":"))
            err (-1, "could not allocate enough memory");

        buffer_put (buffer_1, querystr.s, querystr.len);
        buffer_puts (buffer_1, "tx\n");
        buffer_flush (buffer_1);

        if (resolve (q, type, ip) == -1)
        {
            const char *x = error_str (errno);

            buffer_put (buffer_1, querystr.s, querystr.len);
            buffer_puts (buffer_1, "ALERT:query failed; ");
            buffer_puts (buffer_1, x);
            buffer_puts (buffer_1, "\n");
        }
        else
            parsepacket (tx.packet, tx.packetlen, q, type, control);

        if (dns_domain_equal (q, "\011localhost\0"))
        {
            buffer_put (buffer_1, querystr.s, querystr.len);
            buffer_puts (buffer_1, "ALERT: some caches do not " \
                                        "handle localhost internally\n");
            address_add (q, "\177\0\0\1");
        }
        if (dd (q, "", ip) == 4)
        {
            buffer_put (buffer_1, querystr.s, querystr.len);
            buffer_puts (buffer_1, "ALERT: some caches do not " \
                                        "handle IP addresses internally\n");
            address_add (q, ip);
        }

        buffer_flush (buffer_1);
    }

    return 0;
}
