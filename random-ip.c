/*
 * random-ip.c: This file is part of the `djbdns' project, originally
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
#include <sys/stat.h>
#include <sys/types.h>

#include "version.h"

#include "dns.h"
#include "fmt.h"
#include "scan.h"
#include "buffer.h"

char ip[4];
int ipfixed = 0;
unsigned char tab[256];
unsigned long loops = 10000;

char seed[128];
char strnum[FMT_ULONG];

static char *prog = NULL;

void
usage (void)
{
    printf ("Usage: %s [OPTIONS] [NUM] [BYTE1] [BYTE2] [BYTE3]\n", prog);
    printf ("\n    Generate NUM random IP addresses.\n");
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


int
main (int argc, char *argv[])
{
    char *x = NULL;
    int i = 0, j = 0;
    unsigned long u = 0;
    unsigned char c = 0;

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ? x + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;

    dns_random_init (seed);

    for (i = 0; i < 256; i++)
        tab[i] = i;
    for (j = 256; j > 0; j--)
    {
        i = dns_random (j);
        c = tab[j - 1];
        tab[j - 1] = tab[i];
        tab[i] = c;
    }

    if (*argv)
        scan_ulong (*argv++, &loops);
    if (*argv)
    {
        scan_ulong (*argv++, &u);
        ip[0] = u;
        ipfixed = 1;
    }
    if (*argv)
    {
        scan_ulong (*argv++, &u);
        ip[1] = u;
        ipfixed = 2;
    }
    if (*argv)
    {
        scan_ulong (*argv++, &u);
        ip[2] = u;
        ipfixed = 3;
    }
    if (*argv)
    {
        scan_ulong (*argv++, &u);
        ip[3] = u;
        ipfixed = 4;
    }

    if (ipfixed >= 1)
        if (loops > 16777216)
            loops = 16777216;
    if (ipfixed >= 2)
        if (loops > 65536)
            loops = 65536;
    if (ipfixed >= 3)
        if (loops > 256)
            loops = 256;
    if (ipfixed >= 4)
        if (loops > 1)
            loops = 1;

    while (loops)
    {
        u = --loops;
        for (i = ipfixed; i < 4; i++)
        {
            ip[i] = u & 255;
            u >>= 8;
        }
        if (ipfixed == 3)
        {
            c = ip[3];
            ip[3] = tab[c];
        }
        else if (ipfixed < 3)
        {
            c = 0;
            for (j = 0; j < 100; j++)
            {
                for (i = ipfixed; i < 4; i++)
                {
                    c ^= (unsigned char) ip[i];
                    c = tab[c];
                    ip[i] = c;
                }
            }
        }

        u = (unsigned char) ip[0];
        buffer_put (buffer_1, strnum, fmt_ulong (strnum, u));
        buffer_puts (buffer_1, ".");

        u = (unsigned char) ip[1];
        buffer_put (buffer_1, strnum, fmt_ulong (strnum, u));
        buffer_puts (buffer_1, ".");

        u = (unsigned char) ip[2];
        buffer_put (buffer_1, strnum, fmt_ulong (strnum, u));
        buffer_puts (buffer_1, ".");

        u = (unsigned char) ip[3];
        buffer_put (buffer_1, strnum, fmt_ulong (strnum, u));
        buffer_puts (buffer_1, "\n");
    }
    buffer_flush (buffer_1);

    return 0;
}
