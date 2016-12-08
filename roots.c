/*
 * roots.c: This file is part of the `djbdns' project, originally
 * written by Dr. D J Bernstein and later released under public-domain since
 * late December 2007 (http://cr.yp.to/distributors.html).
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

#include <err.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ip4.h"
#include "dns.h"
#include "str.h"
#include "byte.h"
#include "open.h"
#include "error.h"
#include "roots.h"
#include "openreadclose.h"

static stralloc data;

static int
roots_find (char *q)
{
    int i = 0, j = 0;

    while ((unsigned)i < data.len)
    {
        j = dns_domain_length (data.s + i);
        if (dns_domain_equal (data.s + i, q))
            return i + j;
        i += j;
        i += 64;
    }

    return -1;
}

static int
roots_search (char *q)
{
    int r = 0;

    for (;;)
    {
        if ((r = roots_find (q)) >= 0)
            return r;
        if (!*q)
            return -1; /* user misconfiguration */

        q = q + *q;
        q++;
    }
}

static unsigned char
roots_extract_name (char *dn, const char *s)
{
    unsigned char l = 0, n = 0;

    while (*s)
    {
        n = *s++;
        while (n--)
            dn[l++] = *s++;
        dn[l++] = *s == 0 ? *s : '.';
    }

    return l;
}

int
roots (char servers[64], char *q)
{
    int r = 0;

    if ((r = roots_find (q)) == -1)
        return 0;
    byte_copy (servers, 64, data.s + r);

    return 1;
}

int
roots_same (char *q, char *q2)
{
    return roots_search (q) == roots_search (q2);
}

void
roots_display (void)
{
    char dn[255];
    unsigned short i = 0;

    while (i < data.len)
    {
        unsigned char j = 0, n = 0;

        memset (dn, 0, sizeof (dn));
        n = roots_extract_name (dn, data.s + i);
        warnx ("%s:", dn[0] == '\0' ? "roots" : dn);

        i += n + 1;
        while (j < 64)
        {
            if (data.s[i] != 0)
                warnx("  %hhu.%hhu.%hhu.%hhu",
                        data.s[i], data.s[i+1], data.s[i+2], data.s[i+3]);
            i += 4;
            j += 4;
        }
    }
}

static int
init2 (DIR *dir)
{
    char roots = 0;
    char servers[64];
    static stralloc text;
    static char *q = NULL;
    const char *fqdn = NULL;
    struct dirent *d = NULL;
    int i = 0, j = 0, serverslen = 0;

    errno = 0;
    while ((d = readdir (dir)))
    {
        if (d->d_name[0] == '.')
            continue;

        memset (&text, 0, sizeof (text));
        if (openreadclose (d->d_name, &text, 32) != 1)
            return 0;

        fqdn = d->d_name;
        if (str_equal (fqdn, "roots"))
        {
            roots = 1;
            fqdn = ".";
        }
        if (!dns_domain_fromdot (&q, fqdn, str_len (fqdn)))
            return 0;

        memset (servers, 0, sizeof (servers));
        for (i = 0, j = 0, serverslen = 0; (unsigned)i < text.len; ++i)
        {
            if (text.s[i] == '\n')
            {
                if (serverslen <= 60)
                    if (ip4_scan (text.s + j, servers + serverslen))
                        serverslen += 4;
                j = i + 1;
            }
        }
        if (!stralloc_catb (&data, q, dns_domain_length (q)))
            return 0;
        if (!stralloc_catb (&data, servers, 64))
            return 0;
        errno = 0;
    }
    if (!roots)
        err (-1, "could not access file: servers/roots");

    return !errno;
}

static int
init1 (void)
{
    int r = 0;
    DIR *dir = NULL;

    if (chdir ("servers") == -1)
        return 0;
    if (!(dir = opendir (".")))
        return 0;

    r = init2 (dir);
    closedir (dir);

    return r;
}

int
roots_init (void)
{
    int r = 0, fddir = 0;

    if (!stralloc_copys (&data, ""))
        return 0;
    if ((fddir = open (".", O_RDONLY | O_NDELAY)) == -1)
        return 0;

    r = init1 ();
    if (fchdir (fddir) == -1)
        r = 0;
    close(fddir);

    return r;
}
