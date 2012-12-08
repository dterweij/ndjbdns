/*
 * pickdns-data.c: This file is part of the `djbdns' project, originally
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fmt.h"
#include "ip4.h"
#include "dns.h"
#include "str.h"
#include "byte.h"
#include "scan.h"
#include "case.h"
#include "open.h"
#include "alloc.h"
#include "getln.h"
#include "strerr.h"
#include "buffer.h"
#include "cdb_make.h"
#include "stralloc.h"
#include "gen_allocdefs.h"


struct address
{
    char *name;
    unsigned int namelen;

    char ip[4];
    char location[2];
};

void
ipprefix_cat (stralloc *out, char *s)
{
    char ch = 0;
    unsigned int j = 0;
    unsigned long u = 0;

    for (;;)
    {
        if (*s == '.')
          ++s;
        else
        {
            j = scan_ulong (s, &u);
            if (!j)
                return;

            s += j;
            ch = u;
            if (!stralloc_catb (out, &ch, 1))
                err (-1, "could not allocate enough memory");
        }
    }
}

int
address_diff (struct address *p, struct address *q)
{
    int r = 0;

    r = byte_diff (p->location, 2, q->location);
    if (r < 0)
      return -1;
    if (r > 0)
      return 1;
    if (p->namelen < q->namelen)
      return -1;
    if (p->namelen > q->namelen)
      return 1;

    return case_diffb (p->name, p->namelen, q->name);
}

void
address_sort (struct address *z, unsigned int n)
{
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int p = 0;
    unsigned int q = 0;
    struct address t;

    i = j = n;
    --z;

    while (j > 1)
    {
        if (i > 1)
        {
            --i;
            t = z[i];
        }
        else
        {
            t = z[j];
            z[j] = z[i];
            --j;
        }

        q = i;
        while ((p = q * 2) < j)
        {
            if (address_diff (&z[p + 1], &z[p]) >= 0)
                ++p;
            z[q] = z[p];
            q = p;
        }

        if (p == j)
        {
            z[q] = z[p];
            q = p;
        }
        while ((q > i) && (address_diff (&t, &z[p = q/2]) > 0))
        {
            z[q] = z[p];
            q = p;
        }
        z[q] = t;
    }
}

GEN_ALLOC_typedef(address_alloc, struct address, s, len, a)
GEN_ALLOC_readyplus(address_alloc, struct address,
                    s, len, a, i, n, x, 30, address_alloc_readyplus)
GEN_ALLOC_append(address_alloc, struct address,
        s, len, a, i, n, x, 30,address_alloc_readyplus,address_alloc_append)

static address_alloc x;

int fd;
buffer b;
char bspace[1024];

int fdcdb;
struct cdb_make cdb;
static stralloc key;
static stralloc result;

int match = 1;
static stralloc line;
unsigned long linenum = 0;

#define NUMFIELDS 3
char strnum[FMT_ULONG];
static stralloc f[NUMFIELDS];

void
syntaxerror (const char *why)
{
    strnum[fmt_ulong (strnum, linenum)] = 0;
    err (-1, "unable to parse data line: %s: %s", strnum, why);
}


int main()
{
    char ch = 0;
    struct address t;
    int i = 0, j= 0, k = 0;

    umask(022);
    if (!address_alloc_readyplus (&x, 0))
        err (-1, "could not allocate enough memory");

    fd = open_read("data");
    if (fd == -1)
        err (-1, "could not open file: `data'");
    buffer_init (&b, buffer_unixread, fd, bspace, sizeof bspace);

    fdcdb = open_trunc ("data.tmp");
    if (fdcdb == -1)
        err (-1, "could not create file: `data.tmp'");
    if (cdb_make_start(&cdb, fdcdb) == -1)
        err (-1, "could not create file: `data.tmp'");

    while (match)
    {
        ++linenum;
        if (getln (&b, &line, &match, '\n') == -1)
            err (-1, "could not read line");

        while (line.len)
        {
            ch = line.s[line.len - 1];
            if ((ch != ' ') && (ch != '\t') && (ch != '\n'))
                break;
            --line.len;
        }
        if (!line.len)
            continue;

        j = 1;
        for (i = 0; i < NUMFIELDS; ++i)
        {
            if (j >= line.len)
            {
                if (!stralloc_copys(&f[i],""))
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

        switch (line.s[0])
        {
        default:
            syntaxerror(": unrecognized leading character");

        case '#':
        case '-':
            break;

        case '+':
            byte_zero (&t, sizeof t);
            if (!dns_domain_fromdot (&t.name, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");

            t.namelen = dns_domain_length (t.name);
            case_lowerb (t.name, t.namelen);

            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");
            if (!ip4_scan (f[1].s, t.ip))
                syntaxerror(": malformed IP address");
            if (!stralloc_0 (&f[2]))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[2]))
                err (-1, "could not allocate enough memory");

            byte_copy (t.location, 2, f[2].s);
            if (!address_alloc_append (&x, &t))
                err (-1, "could not allocate enough memory");
            break;

        case '%':
            if (!stralloc_0 (&f[0]))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[0]))
                err (-1, "could not allocate enough memory");
            if (!stralloc_copyb (&result, f[0].s, 2))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");
            if (!stralloc_copys (&key, "%"))
                err (-1, "could not allocate enough memory");
            ipprefix_cat (&key, f[1].s);
            if (cdb_make_add (&cdb, key.s, key.len, result.s, result.len) == -1)
                err (-1, "could not access file: `data.tmp'");
            break;
        }
    }
    close (fd);
    address_sort (x.s, x.len);

    i = 0;
    while (i < x.len)
    {
        for (j = i + 1; j < x.len; ++j)
            if (address_diff (x.s + i, x.s + j))
                break;

        if (!stralloc_copys (&key, "+"))
            err (-1, "could not allocate enough memory");
        if (!stralloc_catb (&key, x.s[i].location, 2))
            err (-1, "could not allocate enough memory");
        if (!stralloc_catb (&key, x.s[i].name, x.s[i].namelen))
            err (-1, "could not allocate enough memory");
        if (!stralloc_copys (&result, ""))
            err (-1, "could not allocate enough memory");

        while (i < j)
            if (!stralloc_catb (&result, x.s[i++].ip, 4))
                err (-1, "could not allocate enough memory");
        if (cdb_make_add (&cdb, key.s, key.len, result.s, result.len) == -1)
            err (-1, "could not access file: `data.tmp'");
    }

    if (cdb_make_finish (&cdb) == -1)
        err (-1, "could not access file: `data.tmp'");
    if (fsync (fdcdb) == -1)
        err (-1, "could not access file: `data.tmp'");
    if (close (fdcdb) == -1)
        err (-1, "could not access file: `data.tmp'"); /* NFS stupidity */
    if (rename("data.tmp","data.cdb") == -1)
        err (-1, "could not move `data.tmp' to `data.cdb'");

    return 0;
}
