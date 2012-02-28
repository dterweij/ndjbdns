/*
 * tcprules.c: This file is part of the `djbdns' project, originally written
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
#include <unistd.h>
#include <getopt.h>

#include "fmt.h"
#include "str.h"
#include "byte.h"
#include "open.h"
#include "scan.h"
#include "getln.h"
#include "buffer.h"
#include "strerr.h"
#include "stralloc.h"
#include "cdb_make.h"

#include "version.h"

char *fn = NULL;
char *fntemp = NULL;
unsigned long linenum = 0;

static char *prog = NULL;

int match = 1;
stralloc key;
stralloc data;
stralloc line;
stralloc address;

struct cdb_make c;

void
usage (void)
{
    printf ("Usage: %s <rules.cdb> <rules.tmp>", prog);
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
die_bad (void)
{
    if (!stralloc_0 (&line))
        err (-1, "could not allocate enough memory");

    err (-1, "unable to parse this line: %s", line.s);
}

void
die_write (void)
{
    err (-1, "unable to write to %s", fntemp);
}

stralloc sanum;
char strnum[FMT_ULONG];

void
getnum (char *buf, int len, unsigned long *u)
{
    if (!stralloc_copyb (&sanum, buf, len))
        err (-1, "could not allocate enough memory");
    if (!stralloc_0 (&sanum))
        err (-1, "could not allocate enough memory");
    if (sanum.s[scan_ulong (sanum.s, u)])
        die_bad ();
}

void
doaddressdata (void)
{
    int i = 0;
    int left = 0, right = 0;
    unsigned long bot = 0, top = 0;

    if (byte_chr (address.s, address.len, '=') == address.len)
    {
        if (byte_chr (address.s, address.len, '@') == address.len)
        {
            i = byte_chr (address.s, address.len, '-');
            if (i < address.len)
            {
                left = byte_rchr (address.s, i, '.');
                left = (left == i) ? 0 : left + 1;

                ++i;
                right = i + byte_chr (address.s + i, address.len - i, '.');

                getnum (address.s + left, i - 1 - left, &bot);
                getnum (address.s + i, right - i, &top);
                if (top > 255)
                    top = 255;

                while (bot <= top)
                {
                    if (!stralloc_copyb (&key, address.s, left))
                        err (-1, "could not allocate enough memory");
                    if (!stralloc_catb (&key, strnum, fmt_ulong (strnum, bot)))
                        err (-1, "could not allocate enough memory");
                    if (!stralloc_catb (&key, address.s + right,
                                              address.len - right))
                        err (-1, "could not allocate enough memory");

                    if (cdb_make_add (&c, key.s, key.len,
                                                 data.s, data.len) == -1)
                        die_write ();
                    ++bot;
                }

                return;
            }
        }
    }

    if (cdb_make_add (&c, address.s, address.len, data.s, data.len) == -1)
        die_write ();
}

int
main (int argc, char *argv[])
{
    buffer b;

    int fd = 0, len = 0;
    int i = 0, colon = 0;
    char *x = NULL, ch = 0;

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ? x + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;
    if (argc < 2)
    {
        usage ();
        exit (0);
    }

    fn = argv[0];
    if (!fn)
        usage ();
    fntemp = argv[1];
    if (!fntemp)
        usage ();

    fd = open_trunc (fntemp);
    if (fd == -1)
        err (-1, "unable to create %s: ", fntemp);
    if (cdb_make_start (&c, fd) == -1)
        die_write ();

    /* buffer_init (&b, buffer_unixread, fddata, bspace, sizeof bspace); */
    while (match)
    {
        if (getln (&b, &line, &match, '\n') == -1)
            errx (-1, "unable to read input: ");
        x = line.s;
        len = line.len;

        if (!len)
            break;
        if (x[0] == '#')
            continue;
        if (x[0] == '\n')
            continue;

        while (len)
        {
            ch = x[len - 1];
            if (ch != '\n')
                if (ch != ' ')
                    if (ch != '\t')
                        break;
            --len;
        }
        line.len = len; /* for die_bad() */

        colon = byte_chr (x, len, ':');
        if (colon == len)
            continue;

        if (!stralloc_copyb (&address, x, colon))
            err (-1, "could not allocate enough memory");
        if (!stralloc_copys (&data, ""))
            err (-1, "could not allocate enough memory");

        x += colon + 1;
        len -= colon + 1;

        if ((len >= 4) && byte_equal (x, 4, "deny"))
        {
            if (!stralloc_catb (&data, "D", 2))
                err (-1, "could not allocate enough memory");
            x += 4;
            len -= 4;
        }
        else if ((len >= 5) && byte_equal (x, 5, "allow"))
        {
            x += 5;
            len -= 5;
        }
        else
            die_bad ();

        while (len)
        {
            switch (*x)
            {
            case ',':
                i = byte_chr (x, len, '=');
                if (i == len)
                    die_bad ();
                if (!stralloc_catb (&data, "+", 1))
                    err (-1, "could not allocate enough memory");
                if (!stralloc_catb (&data, x + 1, i))
                    err (-1, "could not allocate enough memory");

                x += i + 1;
                len -= i + 1;
                if (!len)
                    die_bad ();

                ch = *x;
                x += 1;
                len -= 1;
                i = byte_chr (x, len, ch);
                if (i == len)
                    die_bad ();
                if (!stralloc_catb (&data, x, i))
                    err (-1, "could not allocate enough memory");
                if (!stralloc_0 (&data))
                    err (-1, "could not allocate enough memory");

                x += i + 1;
                len -= i + 1;
                break;

            default:
                die_bad ();
            }
        }
        doaddressdata ();
    }

    if (cdb_make_finish (&c) == -1)
        die_write ();
    if (fsync(fd) == -1)
        die_write ();
    if (close(fd) == -1)
        die_write (); /* NFS stupidity */
    if (rename (fntemp, fn))
        err (-1, "unable to move %s to %s", fntemp, fn);

    return 0;
}
