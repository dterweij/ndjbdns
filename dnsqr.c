/*
 * dnsqr.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * I've modified this file for good and am releasing this new version under
 * GNU General Public License.
 * Copyright (C) 2009 - 2011 Prasad J Pandit
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
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "version.h"

#include "dns.h"
#include "str.h"
#include "byte.h"
#include "scan.h"
#include "error.h"
#include "uint16.h"
#include "strerr.h"
#include "buffer.h"
#include "iopause.h"
#include "parsetype.h"
#include "printpacket.h"


static char *prog = NULL;

void
usage (void)
{
    printf ("Usage: %s <record-type> <domain-name>\n", prog);
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

    if (argc < 2)
    {
        usage ();
        exit (0);
    }

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


char type[2];
static char *q;

static stralloc out;
static char seed[128];

int
main (int argc, char *argv[])
{
    int i = 0;
    uint16 u16 = 0;
    char *x = NULL;

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ?  x + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;

    dns_random_init (seed);

    if (!*argv)
        usage ();
    if (!parsetype (*argv, type))
        errx (-1, "unknown record type `%s'", *argv);

    if (!*++argv)
        usage ();
    if (!dns_domain_fromdot (&q, *argv, str_len (*argv)))
        errx (-1, "could not parse `%s'", *argv);

    if (*++argv)
        usage ();
    if (!stralloc_copys (&out, ""))
        errx (-1, "could not parse");

    uint16_unpack_big (type, &u16);
    if (!stralloc_catulong0 (&out, u16, 0))
        errx (-1, "could not parse");
    if (!stralloc_cats (&out, " "))
        errx (-1, "could not parse");
    if (!dns_domain_todot_cat (&out, q))
        errx (-1, "could not parse");
    if (!stralloc_cats(&out,":\n"))
        errx (-1, "could not parse");

    if (dns_resolve(q,type) == -1)
    {
        if (!stralloc_cats (&out, error_str (errno)))
            errx (-1, "could not parse");
        if (!stralloc_cats (&out, "\n"))
            errx (-1, "could not parse");
    }
    else
    {
        if (dns_resolve_tx.packetlen < 4)
            errx (-1, "could not parse");
        dns_resolve_tx.packet[2] &= ~1;
        dns_resolve_tx.packet[3] &= ~128;
        if (!printpacket_cat (&out, dns_resolve_tx.packet,
                                    dns_resolve_tx.packetlen))
            errx (-1, "could not parse");
    }
    buffer_putflush (buffer_1, out.s, out.len);

    return 0;
}
