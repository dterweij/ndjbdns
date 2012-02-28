/*
 * dnsfilter.c: This file is part of the `djbdns' project, originally written
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
#include <unistd.h>

#include "version.h"

#include "strerr.h"
#include "buffer.h"
#include "stralloc.h"
#include "alloc.h"
#include "dns.h"
#include "ip4.h"
#include "byte.h"
#include "scan.h"
#include "taia.h"
#include "iopause.h"
#include "error.h"

short mode = 0;
static char *prog = NULL;

struct line
{
    stralloc left;
    stralloc middle;
    stralloc right;
    struct dns_transmit dt;
    int flagactive;
    iopause_fd *io;
} *x;

struct line tmp;
unsigned int xnum = 0;
unsigned int xmax = 1000;
unsigned int numactive = 0;
unsigned int maxactive = 10;

static stralloc partial;

int flag0 = 1;
int inbuflen = 0;
char inbuf[1024];
iopause_fd *inio;

int iolen = 0;
iopause_fd *io;

char ip[4];
char servers[64];
char name[DNS_NAME4_DOMAIN];


void
usage (void)
{
    printf ("Usage: %s [OPTIONS]\n", prog);
}

void
printh (void)
{
    usage ();
    printf ("\n Options:\n");
    printf ("%-17s %s\n", "    -c <N>", "do N queries in parallel");
    printf ("%-17s %s\n", "    -h --help", "print this help");
    printf ("%-17s %s\n", "    -l <N>", "read ahead at most N lines");
    printf ("%-17s %s\n", "    -v --version", "print version information");
    printf ("\nReport bugs to <pj.pandit@yahoo.co.in>\n");
}

int
check_option (int argc, char *argv[])
{
    int n = 0, ind = 0;
    const char optstr[] = "+:c:hl:v";
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
        case 'c':
            maxactive = atoi (optarg);
            if (maxactive < 1)
                maxactive = 1;
            if (maxactive > 1000)
                maxactive = 1000;
            break;

        case 'h':
            printh ();
            exit (0);

        case 'l':
            xmax = atoi (optarg);
            if (xmax < 1)
                xmax = 1;
            if (xmax > 1000000)
                xmax = 1000000;
            break;

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
errout (int i)
{
    int j = 0;

    if (!stralloc_copys (&x[i].middle, ":"))
        err (-1, "could not allocate enough memory");
    if (!stralloc_cats (&x[i].middle, error_str (errno)))
        err (-1, "could not allocate enough memory");

    for (j = 0; j < x[i].middle.len; j++)
        if (x[i].middle.s[j] == ' ')
            x[i].middle.s[j] = '-';
}


int
main (int argc, char *argv[])
{
    char *t = NULL;
    int i = 0, j = 0, r = 0;

    struct taia stamp;
    struct taia deadline;

    prog = strdup ((t = strrchr (argv[0], '/')) != NULL ? t + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;


    x = (struct line *) alloc (xmax * sizeof (struct line));
    if (!x)
        err (-1, "could not allocate enough memory");

    io = (iopause_fd *) alloc ((xmax + 1) * sizeof (iopause_fd));
    if (!io)
        err (-1, "could not allocate enough memory");

    if (!stralloc_copys (&partial, ""))
        err (-1, "could not allocate enough memory");


    while (flag0 || inbuflen || partial.len || xnum)
    {
        taia_now (&stamp);
        taia_uint (&deadline, 120);
        taia_add (&deadline, &deadline, &stamp);

        iolen = 0;
        if (flag0)
        {
            if (inbuflen < sizeof inbuf)
            {
                inio = io + iolen++;
                inio->fd = 0;
                inio->events = IOPAUSE_READ;
            }
        }

        for (i = 0; i < xnum; ++i)
        {
            if (x[i].flagactive)
            {
                x[i].io = io + iolen++;
                dns_transmit_io (&x[i].dt, x[i].io, &deadline);
            }
        }

        iopause (io, iolen, &deadline, &stamp);
        if (flag0)
        {
            if (inbuflen < sizeof inbuf)
            {
                if (inio->revents)
                {
                    r = read (0, inbuf + inbuflen, (sizeof inbuf) - inbuflen);
                    if (r <= 0)
                        flag0 = 0;
                    else
                        inbuflen += r;
                }
            }
        }

        for (i = 0;i < xnum;++i)
        {
            if (x[i].flagactive)
            {
                r = dns_transmit_get (&x[i].dt, x[i].io, &stamp);
                if (r == -1)
                {
                    errout (i);
                    x[i].flagactive = 0;
                    --numactive;
                }
                else if (r == 1)
                {
                    if (dns_name_packet (&x[i].middle, x[i].dt.packet,
                                         x[i].dt.packetlen) == -1)
                        errout (i);
                    if (x[i].middle.len)
                    {
                        if (!stralloc_cats(&x[i].left,"="))
                            err (-1, "could not allocate enough memory");
                    }
                    x[i].flagactive = 0;
                    --numactive;
                }
            }
        }

        for (;;)
        {
            if (xnum && !x[0].flagactive)
            {
                buffer_put (buffer_1, x[0].left.s, x[0].left.len);
                buffer_put (buffer_1, x[0].middle.s, x[0].middle.len);
                buffer_put (buffer_1, x[0].right.s, x[0].right.len);
                buffer_flush (buffer_1);

                --xnum;
                tmp = x[0];
                for (i = 0; i < xnum; ++i)
                    x[i] = x[i + 1];
                x[xnum] = tmp;

                continue;
            }

            if ((xnum < xmax) && (numactive < maxactive))
            {
                i = byte_chr (inbuf, inbuflen, '\n');
                if (inbuflen && (i == inbuflen))
                {
                    if (!stralloc_catb (&partial, inbuf, inbuflen))
                        err (-1, "could not allocate enough memory");
                    inbuflen = 0;

                    continue;
                }

                if ((i < inbuflen) || (!flag0 && partial.len))
                {
                    if (i < inbuflen)
                        ++i;
                    if (!stralloc_catb (&partial, inbuf, i))
                        err (-1, "could not allocate enough memory");
                    inbuflen -= i;
                    for (j = 0; j < inbuflen; ++j)
                        inbuf[j] = inbuf[j + i];

                    if (partial.len)
                    {
                        i = byte_chr (partial.s, partial.len, '\n');
                        i = byte_chr (partial.s, i, '\t');
                        i = byte_chr (partial.s, i, ' ');

                        if (!stralloc_copyb (&x[xnum].left, partial.s, i))
                            err (-1, "could not allocate enough memory");
                        if (!stralloc_copys (&x[xnum].middle, ""))
                            err (-1, "could not allocate enough memory");
                        if (!stralloc_copyb (&x[xnum].right, partial.s + i,
                                              partial.len - i))
                            err (-1, "could not allocate enough memory");
                        x[xnum].flagactive = 0;

                        partial.len = i;
                        if (!stralloc_0 (&partial))
                            err (-1, "could not allocate enough memory");
                        if (ip4_scan (partial.s, ip))
                        {
                            dns_name4_domain (name, ip);
                            if (dns_resolvconfip (servers) == -1)
                                err (-1, "could not read `/etc/resolv.conf'");
                            if (dns_transmit_start (&x[xnum].dt, servers,
                                        1, name, DNS_T_PTR, "\0\0\0\0") == -1)
                                errout (xnum);
                            else
                            {
                                x[xnum].flagactive = 1;
                                ++numactive;
                            }
                        }
                        ++xnum;
                    }
                    partial.len = 0;
                    continue;
                }
            }
            break;
        }
    }

    return 0;
}
