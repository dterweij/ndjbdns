/*
 * tinydns-get.c: This file is part of the `djbdns' project, originally
 * written by Dr. D J Bernstein and later released under public-domain
 * since late December 2007 (http://cr.yp.to/distributors.html).
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
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include "version.h"

#include "ip4.h"
#include "dns.h"
#include "str.h"
#include "case.h"
#include "byte.h"
#include "scan.h"
#include "buffer.h"
#include "strerr.h"
#include "uint16.h"
#include "response.h"
#include "stralloc.h"
#include "parsetype.h"
#include "printpacket.h"

static char *prog = NULL;
extern int respond (char *, char *, char *);

void
usage (void)
{
    printf ("Usage: %s <TYPE> <NAME> [IP]\n", prog);
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


static char ip[4];
static char type[2];
static char *q = NULL;

static stralloc out;


int
main (int argc, char *argv[])
{
    char *x = NULL;
    uint16 u16 = 0;

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ? x + 1 : argv[0]);
    u16 = check_option (argc, argv);
    argv += u16;
    argc -= u16;

    if (argc < 2)
    {
        usage ();
        return 0;
    }

    if (!parsetype (*argv, type))
        errx (-1, "could not parse type `%s'", *argv);
    argv++;

    if (!dns_domain_fromdot (&q, *argv, str_len (*argv)))
        errx (-1, "could not parse name `%s'", *argv);
    argv++;    

    if (*argv)
    {
        if (!ip4_scan (*argv, ip))
            errx (-1, "could not parse address `%s'", *argv);
    }

    if (!stralloc_copys (&out, ""))
        err (-1, "could not parse input");
    uint16_unpack_big (type, &u16);

    if (!stralloc_catulong0 (&out, u16, 0))
        err (-1, "could not parse input");
    if (!stralloc_cats (&out, " "))
        err (-1, "could not parse input");
    if (!dns_domain_todot_cat (&out, q))
        err (-1, "could not parse input");
    if (!stralloc_cats (&out, ":\n"))
        err (-1, "could not parse input");

    if (!response_query (q, type, DNS_C_IN))
        err (-1, "could not parse input");

    response[3] &= ~128;
    response[2] &= ~1;
    response[2] |= 4;
    case_lowerb (q, dns_domain_length (q));

    if (byte_equal (type, 2, DNS_T_AXFR))
    {
        response[3] &= ~15;
        response[3] |= 4;
    }
    else if (!respond (q, type, ip))
        goto DONE;

    if (!printpacket_cat (&out, response, response_len))
        err (-1, "could not parse input");

DONE:
    buffer_putflush (buffer_1, out.s, out.len);

    return 0;
}
