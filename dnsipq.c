/*
 * dnsipq.c: This file is part of the `djbdns' project, originally written
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
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "version.h"

#include "ip4.h"
#include "dns.h"
#include "buffer.h"
#include "strerr.h"

char str[IP4_FMT];
static char seed[128];

static stralloc in;
static stralloc out;
static stralloc fqdn;

static char *prog = NULL;

void
usage (void)
{
    printf ("Usage: %s <domain-name> [<domain-name> ...]\n", prog);
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


int
main (int argc,char *argv[])
{
    int i = 0;
    char *x = NULL;

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ?  x + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;

    dns_random_init (seed);
    while (*argv)
    {
        if (!stralloc_copys (&in, *argv))
            err (-1, "could not allocate enough memory");
        if (dns_ip4_qualify (&out, &fqdn, &in) == -1)
            err (-1, "could not find IP address for `%s'", *argv);

        buffer_put (buffer_1, fqdn.s, fqdn.len);
        buffer_puts (buffer_1, " ");
        for (i = 0; i + 4 <= out.len; i += 4)
        {
            buffer_put (buffer_1, str, ip4_fmt (str, out.s + i));
            buffer_puts (buffer_1, " ");
        }
        buffer_puts (buffer_1, "\n");

        ++argv;
    }
    buffer_flush (buffer_1);

    return 0;
}
