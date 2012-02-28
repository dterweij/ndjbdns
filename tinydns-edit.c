/*
 * tinydns-edit.c: This file is part of the `djbdns' project, originally
 * written by Dr. D J Bernstein and later released under public-domain
 * since late December 2007 (http://cr.yp.to/distributors.html).
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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "version.h"

#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include "dns.h"
#include "scan.h"
#include "byte.h"
#include "open.h"
#include "getln.h"
#include "strerr.h"
#include "buffer.h"
#include "stralloc.h"

#define TTL_NS 259200
#define TTL_POSITIVE 86400

char *fn = NULL;
char *fnnew = NULL;
static char *prog = NULL;

char mode;
char targetip[4];
static char *target = NULL;

buffer b;
int fd = 0;
char bspace[1024];

buffer bnew;
int fdnew = 0;
char bnewspace[1024];

int match = 1;
static stralloc line;

#define NUMFIELDS 10
static stralloc f[NUMFIELDS];

static char *d1 = NULL;
static char *d2 = NULL;

char ip[4];
char ipstr[IP4_FMT];
char strnum[FMT_ULONG];

static int used[26];
static char *names[26];

void
put (const char *buf, unsigned int len)
{
    if (buffer_putalign (&bnew, buf, len) == -1)
        err (-1, "could not write `%s'", fnnew);
}


void
usage (void)
{
    printf ("Usage: %s data data.new add ", prog);
    printf ("[ns|childns|host|alias|mx] <domain> <a.b.c.d>\n");
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
    char ch = 0;
    struct stat st;
    unsigned long ttl = 0;
    int i = 0, j = 0, k = 0;

    prog = strdup ((d1 = strrchr (argv[0], '/')) != NULL ? d1 + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;
    d1 = NULL;

    if (argc < 6)
    {
        usage ();
        return -1;
    }

    fn = *argv;

    argv++;
    fnnew = *argv;

    argv++;
    if (str_diff (*argv, "add"))
    {
        usage ();
        return -1;
    }

    argv++;
    if (str_equal (*argv, "ns"))
        mode = '.';
    else if (str_equal (*argv, "childns"))
        mode = '&';
    else if (str_equal (*argv, "host"))
        mode = '=';
    else if (str_equal (*argv, "alias"))
        mode = '+';
    else if (str_equal (*argv, "mx"))
        mode = '@';
    else
        errx (-1, "invalid record type `%s'", *argv);

    argv++;
    if (!dns_domain_fromdot (&target, *argv, str_len (*argv)))
        err (-1, "could not allocate enough memory");

    argv++;
    if (!ip4_scan (*argv, targetip))
        errx (-1, "could not parse IP `%s'", *argv);

    umask(077);

    fd = open_read (fn);
    if (fd == -1)
        err (-1, "could not read from `%s'", fn);
    if (fstat (fd, &st) == -1)
        err (-1, "could not read from `%s'", fn);
    buffer_init (&b, buffer_unixread, fd, bspace, sizeof bspace);

    fdnew = open_trunc (fnnew);
    if (fdnew == -1)
        err (-1, "could not write to `%s'", fnnew);
    if (fchmod (fdnew, st.st_mode & 0644) == -1)
        err (-1, "could not write to `%s'", fnnew);
    buffer_init (&bnew, buffer_unixwrite, fdnew, bnewspace, sizeof bnewspace);

    switch (mode)
    {
    case '.':
    case '&':
        ttl = TTL_NS;
        for (i = 0; i < 26; i++)
        {
            ch = 'a' + i;
            if (!stralloc_copyb (&f[0], &ch, 1))
                err (-1, "could not allocate enough memory");
            if (!stralloc_cats (&f[0], ".ns."))
                err (-1, "could not allocate enough memory");
            if (!dns_domain_todot_cat (&f[0], target))
                err (-1, "could not allocate enough memory");
            if (!dns_domain_fromdot (&names[i], f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
        }
        break;

    case '+':
    case '=':
        ttl = TTL_POSITIVE;
        break;

    case '@':
        ttl = TTL_POSITIVE;
        for (i = 0; i < 26; i++)
        {
            ch = 'a' + i;
            if (!stralloc_copyb (&f[0], &ch, 1))
                err (-1, "could not allocate enough memory");
            if (!stralloc_cats (&f[0], ".mx."))
                err (-1, "could not allocate enough memory");
            if (!dns_domain_todot_cat (&f[0], target))
                err (-1, "could not allocate enough memory");
            if (!dns_domain_fromdot (&names[i], f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
        }
        break;
    }

    while (match)
    {
        if (getln (&b, &line, &match, '\n') == -1)
            err (-1, "could not read from `%s'", fn);

        put (line.s, line.len);
        if (line.len && !match)
            put ("\n", 1);

        while (line.len)
        {
            ch = line.s[line.len - 1];
            if ((ch != ' ') && (ch != '\t') && (ch != '\n'))
                break;

            --line.len;
        }
        if (!line.len || line.s[0] == '#')
            continue;

        j = 1;
        for (i = 0; i < NUMFIELDS; i++)
        {
            if (j >= line.len)
            {
                if (!stralloc_copys (&f[i], ""))
                    err (-1, "could not allocate enough memory");
            }
            else
            {
                k = byte_chr (line.s + j, line.len - j, ':');
                if (!stralloc_copyb (&f[i], line.s + j, k))
                    err (-1, "could not allocate enough memory");
                j += k + 1;
            }
        }

        switch(mode)
        {
        case '.':
        case '&':
            if (line.s[0] == mode)
            {
                if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                    err (-1, "could not allocate enough memory");
                if (dns_domain_equal (d1, target))
                {
                    if (byte_chr (f[2].s, f[2].len, '.') >= f[2].len)
                    {
                        if (!stralloc_cats (&f[2], ".ns."))
                            err (-1, "could not allocate enough memory");
                        if (!stralloc_catb (&f[2], f[0].s, f[0].len))
                            err (-1, "could not allocate enough memory");
                    }
                    if (!dns_domain_fromdot (&d2, f[2].s, f[2].len))
                        err (-1, "could not allocate enough memory");
                    if (!stralloc_0 (&f[3]))
                        err (-1, "could not allocate enough memory");
                    if (!scan_ulong (f[3].s, &ttl))
                        ttl = TTL_NS;
                    for (i = 0; i < 26; i++)
                    {
                        if (dns_domain_equal (d2, names[i]))
                        {
                            used[i] = 1;
                            break;
                        }
                    }
                }
            }
            break;

        case '=':
            if (line.s[0] == '=')
            {
                if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                    err (-1, "could not allocate enough memory");
                if (dns_domain_equal (d1, target))
                    errx (-1, "host name is already used");
                if (!stralloc_0 (&f[1]))
                    err (-1, "could not allocate enough memory");
                if (ip4_scan (f[1].s, ip))
                    if (byte_equal(ip, 4, targetip))
                        errx (-1, "IP address is already used");
            }
            break;

        case '@':
            if (line.s[0] == '@')
            {
                if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                    err (-1, "could not allocate enough memory");
                if (dns_domain_equal (d1, target))
                {
                    if (byte_chr (f[2].s, f[2].len, '.') >= f[2].len)
                    {
                        if (!stralloc_cats (&f[2], ".mx."))
                            err (-1, "could not allocate enough memory");
                        if (!stralloc_catb (&f[2], f[0].s, f[0].len))
                            err (-1, "could not allocate enough memory");
                    }
                    if (!dns_domain_fromdot (&d2, f[2].s, f[2].len))
                        err (-1, "could not allocate enough memory");
                    if (!stralloc_0 (&f[4]))
                        err (-1, "could not allocate enough memory");
                    if (!scan_ulong (f[4].s, &ttl))
                        ttl = TTL_POSITIVE;
                    for (i = 0; i < 26; i++)
                    {
                        if (dns_domain_equal (d2, names[i]))
                        {
                            used[i] = 1;
                            break;
                        }
                    }
                }
            }
            break;
        }
    }

    if (!stralloc_copyb (&f[0], &mode, 1))
        err (-1, "could not allocate enough memory");
    if (!dns_domain_todot_cat (&f[0], target))
        err (-1, "could not allocate enough memory");
    if (!stralloc_cats (&f[0], ":"))
        err (-1, "could not allocate enough memory");
    if (!stralloc_catb (&f[0], ipstr, ip4_fmt (ipstr, targetip)))
        err (-1, "could not allocate enough memory");

    switch (mode)
    {
    case '.':
    case '&':
    case '@':
        for (i = 0; i < 26; i++)
        {
            if (!used[i])
                break;
        }
        if (i >= 26)
            errx (-1, "too many records for domain `%s'", target);

        ch = 'a' + i;
        if (!stralloc_cats (&f[0], ":"))
            err (-1, "could not allocate enough memory");
        if (!stralloc_catb (&f[0], &ch, 1))
            err (-1, "could not allocate enough memory");
        if (mode == '@')
            if (!stralloc_cats (&f[0], ":"))
                err (-1, "could not allocate enough memory");

        break;
    }

    if (!stralloc_cats (&f[0], ":"))
        err (-1, "could not allocate enough memory");
    if (!stralloc_catb (&f[0], strnum, fmt_ulong (strnum, ttl)))
        err (-1, "could not allocate enough memory");
    if (!stralloc_cats (&f[0], "\n"))
        err (-1, "could not allocate enough memory");
    put (f[0].s, f[0].len);

    if (buffer_flush (&bnew) == -1)
        err (-1, "could not write to `%s'", fnnew);
    if (fsync (fdnew) == -1)
        err (-1, "could not write to `%s'", fnnew);
    if (close (fdnew) == -1)
        err (-1, "could not write to `%s'", fnnew); /* NFS dorks */

    if (rename (fnnew, fn) == -1)
        err (-1, "could not move `%s' to `%s'", fnnew, fn);

    return 0;
}
