/*
 * tinydns-data.c: This file is part of the `djbdns' project, originally
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

#include "dns.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include "byte.h"
#include "case.h"
#include "scan.h"
#include "open.h"
#include "getln.h"
#include "buffer.h"
#include "strerr.h"
#include "uint16.h"
#include "uint32.h"
#include "cdb_make.h"
#include "stralloc.h"

#define TTL_NS          259200
#define TTL_POSITIVE    86400
#define TTL_NEGATIVE    2560

static char *prog = NULL;

void
ttdparse (stralloc *sa, char ttd[8])
{
    char ch = 0;
    unsigned int i = 0;

    byte_zero (ttd, 8);
    for (i = 0; (i < 16) && (i < sa->len); i++)
    {
        ch = sa->s[i];
        if ((ch >= '0') && (ch <= '9'))
            ch -= '0';
        else if ((ch >= 'a') && (ch <= 'f'))
            ch -= 'a' - 10;
        else
            ch = 0;

        if (!(i & 1))
            ch <<= 4;
        ttd[i >> 1] |= ch;
    }
}


void
locparse (stralloc *sa, char loc[2])
{
    loc[0] = (sa->len > 0) ? sa->s[0] : 0;
    loc[1] = (sa->len > 1) ? sa->s[1] : 0;
}


void
ipprefix_cat (stralloc *out, char *s)
{
    char ch = 0;
    unsigned int j = 0;
    unsigned long u = 0;

    for (;;)
    {
        if (*s == '.')
            s++;
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


void
txtparse (stralloc *sa)
{
    char ch = 0;
    unsigned int i = 0;
    unsigned int j = 0;

    i = j = 0;
    while (i < sa->len)
    {
        ch = sa->s[i++];
        if (ch == '\\')
        {
            if (i >= sa->len)
                break;
            ch = sa->s[i++];
            if ((ch >= '0') && (ch <= '7'))
            {
                ch -= '0';
                if ((i < sa->len) && (sa->s[i] >= '0') && (sa->s[i] <= '7'))
                {
                    ch <<= 3;
                    ch += sa->s[i++] - '0';
                    if ((i < sa->len) && (sa->s[i] >= '0')
                        && (sa->s[i] <= '7'))
                    {
                        ch <<= 3;
                        ch += sa->s[i++] - '0';
                    }
                }
            }
        }
        sa->s[j++] = ch;
    }
    sa->len = j;
}


char defaultsoa[20];

void
defaultsoa_init (int fd)
{
    struct stat st;

    if (fstat (fd, &st) == -1)
        err (-1, "unable to stat data");

    uint32_pack_big (defaultsoa, st.st_mtime);
    if (byte_equal (defaultsoa, 4, "\0\0\0\0"))
        defaultsoa[3] = 1;
    byte_copy (defaultsoa + 4, 16,
                    "\0\0\100\000\0\0\010\000\0\020\000\000\0\0\012\000");
}


int fdcdb;
struct cdb_make cdb;
static stralloc key;
static stralloc result;


void
rr_add (const char *buf, unsigned int len)
{
    if (!stralloc_catb (&result, buf, len))
        err (-1, "could not allocate enough memory");
}


void
rr_addname (const char *d)
{
    rr_add (d, dns_domain_length (d));
}


void
rr_start (const char type[2], unsigned long ttl,
                              const char ttd[8], const char loc[2])
{
    char buf[4];

    if (!stralloc_copyb (&result, type, 2))
        err (-1, "could not allocate enough memory");

    if (byte_equal (loc, 2, "\0\0"))
        rr_add ("=", 1);
    else
    {
        rr_add (">", 1);
        rr_add (loc, 2);
    }

    uint32_pack_big (buf, ttl);

    rr_add (buf, 4);
    rr_add (ttd, 8);
}


void
rr_finish (const char *owner)
{
    if (byte_equal (owner, 2, "\1*"))
    {
        owner += 2;
        result.s[2] -= 19;
    }

    if (!stralloc_copyb (&key, owner, dns_domain_length (owner)))
        err (-1, "could not allocate enough memory");

    case_lowerb (key.s, key.len);

    if (cdb_make_add (&cdb, key.s, key.len, result.s, result.len) == -1)
        errx (-1, "could not create file `data.tmp'");
}


buffer b;
char bspace[1024];

int match = 1;
static stralloc line;
unsigned long linenum = 0;

#define NUMFIELDS 15
static stralloc f[NUMFIELDS];

static char *d1;
static char *d2;
char dptr[DNS_NAME4_DOMAIN];

char strnum[FMT_ULONG];


void
syntaxerror (const char *why)
{
    strnum[fmt_ulong (strnum, linenum)] = 0;
    errx (-1, "could not parse data line: %s: %s", strnum, why);
}


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
main(int argc, char *argv[])
{
    int fddata = 0;
    int i = 0, j = 0, k = 0;

    unsigned long u = 0;
    unsigned long ttl = 0;

    char ch = 0;
    char *x = NULL;
    char ttd[8], loc[2];
    char ip[4], type[2];
    char soa[20], buf[4];

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ? x + 1 : argv[0]);
    i = check_option (argc, argv);
    argv += i;
    argc -= i;

    umask(022);

    if ((fddata = open_read ("data")) == -1)
        err (-1, "could not open file `data'");
    defaultsoa_init (fddata);

    buffer_init (&b, buffer_unixread, fddata, bspace, sizeof bspace);

    if ((fdcdb = open_trunc ("data.tmp")) == -1)
        err (-1, "could not create file `data.tmp'");
    if (cdb_make_start (&cdb, fdcdb) == -1)
        err (-1, "could not create file `data.tmp'");

    while (match)
    {
        linenum++;
        if (getln (&b, &line, &match, '\n') == -1)
            err (-1, "could not read line: %d", linenum);

        while (line.len)
        {
            ch = line.s[line.len - 1];
            if ((ch != ' ') && (ch != '\t') && (ch != '\n'))
                break;

            --line.len;
        }
        if (!line.len)
            continue;
        if (line.s[0] == '#')
            continue;
        if (line.s[0] == '-')
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

        switch (line.s[0])
        {
        case '%':
            locparse (&f[0], loc);

            if (!stralloc_copyb (&key, "\0%", 2))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");

            ipprefix_cat (&key, f[1].s);

            if (cdb_make_add(&cdb,key.s,key.len,loc,2) == -1)
                err (-1, "could not create file `data.tmp'");

            break;

        case 'Z':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");

            if (!stralloc_0 (&f[3]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[3].s, &u))
                uint32_unpack_big (defaultsoa, &u);
            uint32_pack_big (soa, u);

            if (!stralloc_0 (&f[4]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[4].s, &u))
                uint32_unpack_big (defaultsoa + 4, &u);
            uint32_pack_big (soa + 4, u);

            if (!stralloc_0 (&f[5]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[5].s, &u))
                uint32_unpack_big (defaultsoa + 8, &u);
            uint32_pack_big (soa + 8, u);

            if (!stralloc_0 (&f[6]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[6].s, &u))
                uint32_unpack_big (defaultsoa + 12, &u);
            uint32_pack_big (soa + 12, u);

            if (!stralloc_0 (&f[7]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[7].s, &u))
                uint32_unpack_big (defaultsoa + 16, &u);
            uint32_pack_big (soa + 16, u);

            if (!stralloc_0 (&f[8]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong(f[8].s,&ttl))
                ttl = TTL_NEGATIVE;

            ttdparse (&f[9], ttd);
            locparse (&f[10], loc);

            rr_start (DNS_T_SOA, ttl, ttd, loc);
            if (!dns_domain_fromdot (&d2, f[1].s, f[1].len))
                err (-1, "could not allocate enough memory");

            rr_addname (d2);
            if (!dns_domain_fromdot (&d2, f[2].s, f[2].len))
                err (-1, "could not allocate enough memory");

            rr_addname (d2);
            rr_add (soa, 20);
            rr_finish (d1);

            break;

        case '.':
        case '&':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[3]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[3].s, &ttl))
                ttl = TTL_NS;

            ttdparse (&f[4], ttd);
            locparse (&f[5], loc);

            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");

            if (byte_chr (f[2].s, f[2].len, '.') >= f[2].len)
            {
                if (!stralloc_cats (&f[2], ".ns."))
                    err (-1, "could not allocate enough memory");
                if (!stralloc_catb (&f[2], f[0].s, f[0].len))
                    err (-1, "could not allocate enough memory");
            }
            if (!dns_domain_fromdot (&d2, f[2].s, f[2].len))
                err (-1, "could not allocate enough memory");

            if (line.s[0] == '.')
            {
                rr_start (DNS_T_SOA, ttl ? TTL_NEGATIVE : 0, ttd, loc);
                rr_addname (d2);

                rr_add ("\12hostmaster", 11);
                rr_addname (d1);

                rr_add (defaultsoa, 20);
                rr_finish (d1);
            }

            rr_start (DNS_T_NS, ttl, ttd, loc);
            rr_addname (d2);
            rr_finish (d1);

            if (ip4_scan (f[1].s, ip))
            {
                rr_start (DNS_T_A, ttl, ttd, loc);
                rr_add (ip, 4);
                rr_finish (d2);
            }

            break;

        case '+':
        case '=':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[2]))
                err (-1, "could not allocate enough memory");

            if (!scan_ulong (f[2].s, &ttl))
                ttl = TTL_POSITIVE;

            ttdparse (&f[3], ttd);
            locparse (&f[4], loc);

            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");

            if (ip4_scan (f[1].s, ip))
            {
                rr_start (DNS_T_A, ttl, ttd, loc);
                rr_add (ip, 4);
                rr_finish (d1);

                if (line.s[0] == '=')
                {
                    dns_name4_domain (dptr,ip);
                    rr_start (DNS_T_PTR, ttl, ttd, loc);
                    rr_addname (d1);
                    rr_finish (dptr);
                }
            }
            break;

        case '@':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[4]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[4].s, &ttl))
                ttl = TTL_POSITIVE;

            ttdparse (&f[5], ttd);
            locparse (&f[6], loc);

            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");

            if (byte_chr (f[2].s, f[2].len, '.') >= f[2].len)
            {
                if (!stralloc_cats (&f[2], ".mx."))
                    err (-1, "could not allocate enough memory");
                if (!stralloc_catb (&f[2], f[0].s, f[0].len))
                    err (-1, "could not allocate enough memory");
            }
            if (!dns_domain_fromdot (&d2, f[2].s, f[2].len))
                err (-1, "could not allocate enough memory");

            if (!stralloc_0 (&f[3]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[3].s, &u))
                u = 0;

            rr_start (DNS_T_MX, ttl, ttd, loc);
            uint16_pack_big (buf, u);
            rr_add (buf, 2);
            rr_addname (d2);
            rr_finish (d1);

            if (ip4_scan (f[1].s, ip))
            {
                rr_start (DNS_T_A, ttl, ttd, loc);
                rr_add (ip, 4);
                rr_finish (d2);
            }
            break;

        case '^':
        case 'C':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
            if (!dns_domain_fromdot (&d2, f[1].s, f[1].len))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[2]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[2].s, &ttl))
                ttl = TTL_POSITIVE;

            ttdparse (&f[3], ttd);
            locparse (&f[4], loc);

            if (line.s[0] == 'C')
                rr_start (DNS_T_CNAME, ttl, ttd, loc);
            else
                rr_start (DNS_T_PTR, ttl, ttd, loc);

            rr_addname (d2);
            rr_finish (d1);

            break;

        case '\'':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[2]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[2].s, &ttl))
                ttl = TTL_POSITIVE;

            ttdparse (&f[3], ttd);
            locparse (&f[4], loc);

            rr_start (DNS_T_TXT, ttl, ttd, loc);

            txtparse (&f[1]);
            i = 0;
            while (i < f[1].len)
            {
                k = f[1].len - i;
                if (k > 127)
                    k = 127;
                ch = k;
                rr_add (&ch, 1);
                rr_add (f[1].s + i, k);
                i += k;
            }

            rr_finish (d1);
            break;

        case ':':
            if (!dns_domain_fromdot (&d1, f[0].s, f[0].len))
                err (-1, "could not allocate enough memory");
            if (!stralloc_0 (&f[3]))
                err (-1, "could not allocate enough memory");
            if (!scan_ulong (f[3].s, &ttl))
                ttl = TTL_POSITIVE;

            ttdparse (&f[4], ttd);
            locparse (&f[5], loc);

            if (!stralloc_0 (&f[1]))
                err (-1, "could not allocate enough memory");
            scan_ulong (f[1].s, &u);
            uint16_pack_big (type, u);
            if (byte_equal (type, 2, DNS_T_AXFR))
                syntaxerror (": type AXFR prohibited");
            if (byte_equal (type, 2, "\0\0"))
              syntaxerror (": type 0 prohibited");
            if (byte_equal (type, 2, DNS_T_SOA))
              syntaxerror (": type SOA prohibited");
            if (byte_equal (type, 2, DNS_T_NS))
              syntaxerror (": type NS prohibited");
            if (byte_equal (type, 2, DNS_T_CNAME))
              syntaxerror (": type CNAME prohibited");
            if (byte_equal (type, 2, DNS_T_PTR))
              syntaxerror (": type PTR prohibited");
            if (byte_equal (type, 2, DNS_T_MX))
              syntaxerror (": type MX prohibited");

            txtparse (&f[2]);

            rr_start (type, ttl, ttd, loc);
            rr_add (f[2].s, f[2].len);
            rr_finish (d1);

            break;

        default:
            syntaxerror (": unrecognized leading character");
        }
    }

    if (cdb_make_finish (&cdb) == -1)
        err (-1, "could not create file `data.tmp'");
    if (fsync (fdcdb) == -1)
        err (-1, "could not create file `data.tmp'");
    if (close (fdcdb) == -1)
        err (-1, "could not create file `data.tmp'"); /* NFS stupidity */
    if (rename ("data.tmp", "data.cdb") == -1)
        err (-1, "could not move `data.tmp' to `data.cdb'");

    return 0;
}
