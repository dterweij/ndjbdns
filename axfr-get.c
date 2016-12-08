/*
 * axfr-get.c: This file is part of the `ndjbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * Copyright (C) 2009 - 2014 Prasad J Pandit
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
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "version.h"

#include "dns.h"
#include "str.h"
#include "ip4.h"
#include "byte.h"
#include "open.h"
#include "scan.h"
#include "error.h"
#include "getln.h"
#include "buffer.h"
#include "strerr.h"
#include "uint32.h"
#include "uint16.h"
#include "stralloc.h"
#include "timeoutread.h"
#include "timeoutwrite.h"

static char *prog = NULL;

unsigned int
x_copy (char *buf, unsigned int len,
        unsigned int pos, char *out, unsigned int outlen)
{
    pos = dns_packet_copy (buf, len, pos, out, outlen);
    if (!pos)
        err (-1, "could not parse AXFR results");

    return pos;
}

unsigned int
x_getname (char *buf, unsigned int len, unsigned int pos, char **out)
{
    pos = dns_packet_getname (buf, len, pos, out);
    if (!pos)
        err (-1, "could not parse AXFR results");

    return pos;
}

unsigned int
x_skipname (char *buf, unsigned int len, unsigned int pos)
{
    pos = dns_packet_skipname (buf, len, pos);
    if (!pos)
        err (-1, "could not parse AXFR results");

    return pos;
}

unsigned int zonelen;
static char *zone = NULL;
char *fn = NULL, *fntmp = NULL;

int
saferead (int fd, char *buf, unsigned int len)
{
    int r;

    r = timeoutread (60, fd, buf, len);
    if (r == 0)
    {
        errno = error_proto;
        err (-1, "could not parse AXFR results");
    }
    if (r <= 0)
        err (-1, "could not read from network");

    return r;
}

int
safewrite (int fd, char *buf, unsigned int len)
{
    int r;

    r = timeoutwrite (60, fd, buf, len);
    if (r <= 0)
        err (-1, "could not write to network");

    return r;
}

char netreadspace[1024];
buffer netread = BUFFER_INIT (saferead, 6,
                                netreadspace, sizeof (netreadspace));
char netwritespace[1024];
buffer netwrite = BUFFER_INIT (safewrite, 7,
                                netwritespace, sizeof (netwritespace));

void
netget (char *buf, unsigned int len)
{
    int r;

    while (len > 0)
    {
        r = buffer_get (&netread, buf, len);
        buf += r;
        len -= r;
    }
}

int fd;
buffer b;
char bspace[1024];

void
put (char *buf, unsigned int len)
{
    if (buffer_put (&b, buf, len) == -1)
        err (-1, "unable to write %s", fntmp);
}

int
printable (char ch)
{
    if (ch == '.')
        return 1;
    if ((ch >= 'a') && (ch <= 'z'))
        return 1;
    if ((ch >= '0') && (ch <= '9'))
        return 1;
    if ((ch >= 'A') && (ch <= 'Z'))
        return 1;
    if (ch == '-')
        return 1;

    return 0;
}

static char *d1;
static char *d2;
static char *d3;

stralloc line;
int match, numsoa;

unsigned int
doit (char *buf, unsigned int len, unsigned int pos)
{
    int i;
    char data[20];
    uint32 ttl, u32;
    uint16 dlen, typenum;

    pos = x_getname (buf, len, pos, &d1);
    pos = x_copy (buf, len, pos, data, 10);
    uint16_unpack_big (data, &typenum);
    uint32_unpack_big (data + 4, &ttl);
    uint16_unpack_big (data + 8, &dlen);
    if (len - pos < dlen)
    {
        errno = error_proto;
        return 0;
    }
    len = pos + dlen;

    if (!dns_domain_suffix (d1, zone))
        return len;
    if (byte_diff (data + 2, 2, DNS_C_IN))
        return len;

    if (byte_equal (data, 2, DNS_T_SOA))
    {
        if (++numsoa >= 2)
            return len;

        pos = x_getname (buf, len, pos, &d2);
        pos = x_getname (buf, len, pos, &d3);
        x_copy (buf, len, pos, data, 20);
        uint32_unpack_big (data, &u32);

        if (!stralloc_copys (&line, "#"))
            return 0;
        if (!stralloc_catulong0 (&line, u32, 0))
            return 0;
        if (!stralloc_cats (&line, " auto axfr-get\n"))
            return 0;
        if (!stralloc_cats (&line, "Z"))
            return 0;
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, ":"))
            return 0;
        if (!dns_domain_todot_cat (&line, d2))
            return 0;
        if (!stralloc_cats (&line, ".:"))
            return 0;
        if (!dns_domain_todot_cat (&line, d3))
            return 0;
        if (!stralloc_cats (&line, "."))
            return 0;
        for (i = 0; i < 5; ++i)
        {
            uint32_unpack_big (data + 4 * i, &u32);
            if (!stralloc_cats (&line, ":"))
                return 0;
            if (!stralloc_catulong0 (&line, u32, 0))
                return 0;
        }
    }
    else if (byte_equal (data, 2, DNS_T_NS))
    {
        if (!stralloc_copys (&line, "&"))
            return 0;
        if (byte_equal (d1, 2, "\1*"))
        {
            errno = error_proto;
            return 0;
        }
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, "::"))
            return 0;

        x_getname (buf, len, pos, &d1);
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, "."))
            return 0;
    }
    else if (byte_equal (data, 2, DNS_T_CNAME))
    {
        if (!stralloc_copys (&line, "C"))
            return 0;
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, ":"))
            return 0;

        x_getname (buf, len, pos, &d1);
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, "."))
            return 0;
    }
    else if (byte_equal (data, 2, DNS_T_PTR))
    {
        if (!stralloc_copys (&line, "^"))
            return 0;
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, ":"))
            return 0;

        x_getname (buf, len, pos, &d1);
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, "."))
            return 0;
    }
    else if (byte_equal(data,2,DNS_T_MX))
    {
        uint16 dist;
        if (!stralloc_copys (&line, "@"))
            return 0;
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, "::"))
            return 0;

        pos = x_copy (buf, len, pos, data, 2);
        uint16_unpack_big (data, &dist);

        x_getname (buf, len, pos, &d1);
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, ".:"))
            return 0;
        if (!stralloc_catulong0 (&line, dist, 0))
            return 0;
    }
    else if (byte_equal (data, 2, DNS_T_A) && (dlen == 4))
    {
        char ipstr[IP4_FMT];
        if (!stralloc_copys (&line, "+"))
            return 0;
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, ":"))
            return 0;

        x_copy (buf, len, pos, data, 4);
        if (!stralloc_catb (&line, ipstr, ip4_fmt (ipstr, data)))
            return 0;
    }
    else
    {
        unsigned char ch;
        unsigned char ch2;

        if (!stralloc_copys (&line, ":"))
            return 0;
        if (!dns_domain_todot_cat (&line, d1))
            return 0;
        if (!stralloc_cats (&line, ":"))
            return 0;
        if (!stralloc_catulong0 (&line, typenum, 0))
            return 0;
        if (!stralloc_cats (&line, ":"))
            return 0;
        for (i = 0; i < dlen; ++i)
        {
            pos = x_copy (buf, len, pos, data, 1);
            ch = data[0];
            if (printable (ch))
            {
                if (!stralloc_catb (&line, (char *)&ch, 1))
                    return 0;
            }
            else
            {
                if (!stralloc_cats (&line, "\\"))
                    return 0;

                ch2 = '0' + ((ch >> 6) & 7);
                if (!stralloc_catb (&line, (char *)&ch2, 1))
                    return 0;

                ch2 = '0' + ((ch >> 3) & 7);
                if (!stralloc_catb (&line, (char *)&ch2, 1))
                    return 0;

                ch2 = '0' + (ch & 7);
                if (!stralloc_catb (&line, (char *)&ch2, 1))
                    return 0;
            }
        }
    }
    if (!stralloc_cats (&line, ":"))
        return 0;
    if (!stralloc_catulong0 (&line, ttl, 0))
        return 0;
    if (!stralloc_cats (&line, "\n"))
        return 0;
    put (line.s, line.len);

    return len;
}

static void
usage (void)
{
    printf ("Usage: %s [OPTIONS] <zone> <fn> <fn.tmp>\n",  prog);
}

static void
printh (void)
{
    usage ();
    printf ("\n Options:\n");
    printf ("%-17s %s\n", "    -h --help", "print this help");
    printf ("%-17s %s\n", "    -v --version", "print version information");
    printf ("\nReport bugs to <pj.pandit@yahoo.co.in>\n");
}

static int
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
            printf ("%s is part of ndjbdns version %s\n", prog, VERSION);
            exit (0);

        default:
            errx (-1, "unknown option `%c', see: --help", optopt);
        }
    }

    return optind;
}

stralloc packet;

int
main (int argc, char **argv)
{
    char out[20];
    unsigned long u;
    unsigned int pos;

    uint16 dlen;
    uint16 numqueries;
    uint16 numanswers;
    uint32 oldserial = 0;
    uint32 newserial = 0;

    prog = strdup ((fn = strrchr (argv[0], '/')) != NULL ? fn + 1 : argv[0]);
    pos = check_option (argc, argv);
    argc -= pos;
    argv += pos;
    if (argc < 3 || !*++argv)
    {
        usage ();
        return -1;
    }

    if (!dns_domain_fromdot (&zone, *argv, str_len (*argv)))
        err (-1, "could not generate AXFR query");
    zonelen = dns_domain_length (zone);

    fn = *++argv;
    fntmp = *++argv;
    fd = open_read (fn);
    if (fd == -1)
    {
        if (errno != error_noent)
            err (-1, "could not read from %s", fn);
    }
    else
    {
        buffer_init (&b, buffer_unixread, fd, bspace, sizeof (bspace));
        if (getln (&b, &line, &match, '\n') == -1)
            err (-1, "could not read from %s", fn);
        if (!stralloc_0 (&line))
            err (-1, "could not read from %s", fn);
        if (line.s[0] == '#')
        {
            scan_ulong (line.s + 1, &u);
            oldserial = u;
        }
        close (fd);
    }

    if (!stralloc_copyb (&packet, "\0\0\0\0\0\1\0\0\0\0\0\0", 12))
        err (-1 ,"could not generate AXFR query");
    if (!stralloc_catb (&packet, zone, zonelen))
        err (-1 ,"could not generate AXFR query");
    if (!stralloc_catb (&packet, DNS_T_SOA DNS_C_IN, 4))
        err (-1 ,"could not generate AXFR query");

    uint16_pack_big (out, packet.len);
    buffer_put (&netwrite, out, 2);
    buffer_put (&netwrite, packet.s, packet.len);
    buffer_flush (&netwrite);

    netget (out, 2);
    uint16_unpack_big (out, &dlen);
    if (!stralloc_ready (&packet, dlen))
        err (-1, "could not parse AXFR results");
    netget (packet.s, dlen);
    packet.len = dlen;

    pos = x_copy (packet.s, packet.len, 0, out, 12);
    uint16_unpack_big (out + 4, &numqueries);
    uint16_unpack_big (out + 6, &numanswers);

    while (numqueries)
    {
        --numqueries;
        pos = x_skipname (packet.s, packet.len, pos);
        pos += 4;
    }

    if (!numanswers)
    {
        errno = error_proto;
        err (-1, "could not parse AXFR results");
    }
    pos = x_getname (packet.s, packet.len, pos, &d1);
    if (!dns_domain_equal(zone,d1))
    {
        errno = error_proto;
        err (-1, "could not parse AXFR results");
    }
    pos = x_copy (packet.s, packet.len, pos, out, 10);
    if (byte_diff (out, 4, DNS_T_SOA DNS_C_IN))
    {
        errno = error_proto;
        err (-1, "could not parse AXFR results");
    }
    pos = x_skipname (packet.s, packet.len, pos);
    pos = x_skipname (packet.s, packet.len, pos);
    pos = x_copy (packet.s, packet.len, pos, out, 4);

    uint32_unpack_big (out, &newserial);

    if ((oldserial && newserial) /*allow 0 for very recently modified zones*/
        && (oldserial == newserial))
        exit (0); /* allow serial numbers to move backwards */

    fd = open_trunc (fntmp);
    if (fd == -1)
        err (-1, "could not write to %s", fntmp);
    buffer_init (&b, buffer_unixwrite, fd, bspace, sizeof (bspace));

    if (!stralloc_copyb (&packet, "\0\0\0\0\0\1\0\0\0\0\0\0", 12))
        err (-1 ,"could not generate AXFR query");
    if (!stralloc_catb (&packet, zone, zonelen))
        err (-1 ,"could not generate AXFR query");
    if (!stralloc_catb (&packet, DNS_T_AXFR DNS_C_IN, 4))
        err (-1 ,"could not generate AXFR query");

    uint16_pack_big (out, packet.len);
    buffer_put (&netwrite, out, 2);
    buffer_put (&netwrite, packet.s, packet.len);
    buffer_flush (&netwrite);

    numsoa = 0;
    while (numsoa < 2)
    {
        netget (out, 2);
        uint16_unpack_big (out, &dlen);
        if (!stralloc_ready (&packet, dlen))
            err (-1, "could not parse AXFR results");
        netget (packet.s, dlen);
        packet.len = dlen;

        pos = x_copy (packet.s, packet.len, 0, out, 12);
        uint16_unpack_big (out + 4, &numqueries);

        while (numqueries)
        {
            --numqueries;
            pos = x_skipname (packet.s, packet.len, pos);
            pos += 4;
        }
        while (pos < packet.len)
        {
            pos = doit (packet.s, packet.len, pos);
            if (!pos)
                err (-1, "could not parse AXFR results");
        }
    }

    if (buffer_flush(&b) == -1)
        err (-1, "could not write to %s", fntmp);
    if (fsync(fd) == -1)
        err (-1, "could not write to %s", fntmp);
    if (close (fd) == -1)
        err (-1, "could not write to %s", fntmp); /* NFS dorks */
    if (rename (fntmp, fn) == -1)
        err (-1, "could not move %s to %s", fntmp, fn);

    return 0;
}
