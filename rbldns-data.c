/*
 * rbldns-data.c: This file is part of the `ndjbdns' project, originally
 * written by Dr. D J Bernstein and later released under public-domain since
 * late December 2007 (http://cr.yp.to/distributors.html).
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
#include <sys/stat.h>
#include <sys/types.h>

#include "fmt.h"
#include "ip4.h"
#include "byte.h"
#include "open.h"
#include "scan.h"
#include "getln.h"
#include "strerr.h"
#include "buffer.h"
#include "cdb_make.h"
#include "stralloc.h"

buffer b;
int fd = 0;
char bspace[1024];

int fdcdb = 0;
struct cdb_make cdb;
static stralloc tmp;

int match = 1;
static stralloc line;
unsigned long linenum = 0;

int
main (int argc, char *argv[])
{
    char ip[4], ch = 0;
    unsigned long u = 0;
    unsigned int j = 0, k = 0;

    umask(022);
    fd = open_read ("data");
    if (fd == -1)
        err (-1, "could not open file: `%s'", "data");
    buffer_init (&b, buffer_unixread, fd, bspace, sizeof (bspace));

    fdcdb = open_trunc ("data.tmp");
    if (fdcdb == -1)
        err (-1, "could not open file: `%s'", "data.tmp");
    if (cdb_make_start (&cdb, fdcdb) == -1)
        err (-1, "could not write to file: `%s'", "data.tmp");

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

        switch (line.s[0])
        {
        default:
            err (-1, "could not parse data line: invalid leading character");

        case '#':
            break;

        case ':':
            j = byte_chr (line.s + 1, line.len - 1, ':');
            if (j >= line.len - 1)
                err (-1, "could not parse data line: missing colon");
            if (ip4_scan (line.s + 1, ip) != j)
                err (-1, "could not parse data line: malformed IP address");
            if (!stralloc_copyb (&tmp, ip, 4))
                err (-1, "could not allocate enough memory");
            if (!stralloc_catb (&tmp, line.s + j + 2, line.len - j - 2))
                err (-1, "could not allocate enough memory");
            if (cdb_make_add (&cdb, "", 0, tmp.s, tmp.len) == -1)
                err (-1, "could not write to file: `%s'", "data.tmp");
            break;

        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            if (!stralloc_0 (&line))
                err (-1, "could not allocate enough memory");
            if (!stralloc_copys (&tmp, ""))
                err (-1, "could not allocate enough memory");
            for (j = 0; ; j++)
            {
                k = scan_ulong (line.s + j, &u);
                if (!k)
                    break;

                ch = u;
                if (!stralloc_catb (&tmp, &ch, 1))
                    err (-1, "could not allocate enough memory");

                j += k;
                if (line.s[j] != '.')
                    break;
            }
            if (!stralloc_catb (&tmp, "\0\0\0\0", 4))
                err (-1, "could not allocate enough memory");

            tmp.len = 4;
            if (line.s[j] == '/')
                scan_ulong (line.s + j + 1, &u);
            else
                u = 32;

            u = (u <= 32) ? u : 32;
            ch = u;

            if (!stralloc_catb (&tmp, &ch, 1))
                err (-1, "could not allocate enough memory");
            if (cdb_make_add (&cdb, tmp.s, tmp.len, "", 0) == -1)
                err (-1, "could not write to file: `%s'", "data.tmp");
            break;
        }
    }

    if (cdb_make_finish (&cdb) == -1)
        err (-1, "could not write to file: `%s'", "data.tmp");
    if (fsync (fdcdb) == -1)
        err (-1, "could not write to file: `%s'", "data.tmp");
    if (close (fdcdb) == -1)
        err (-1, "could not close file: `%s'", "data.tmp"); /* NFS stupidity */
    if (rename ("data.tmp", "data.cdb") == -1)
        err (-1, "could not move data.tmp to data.cdb");

    return 0;
}
