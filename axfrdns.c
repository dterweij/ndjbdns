/*
 * axfrdns.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
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
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>

#include "version.h"

#include "dns.h"
#include "env.h"
#include "ip4.h"
#include "tai.h"
#include "cdb.h"
#include "str.h"
#include "byte.h"
#include "case.h"
#include "qlog.h"
#include "scan.h"
#include "open.h"
#include "seek.h"
#include "uint32.h"
#include "uint16.h"
#include "buffer.h"
#include "common.h"
#include "strerr.h"
#include "stralloc.h"
#include "response.h"
#include "droproot.h"
#include "timeoutread.h"
#include "timeoutwrite.h"

#define PIDFILE "/var/run/axfrdns.pid"
#define LOGFILE "/var/log/axfrdns.log"
#define CFGFILE SYSCONFDIR"/ndjbdns/axfrdns.conf"

static char *prog = NULL;
short mode = 0, debug_level = 0;

extern int respond(char *,char *,char *);

int
safewrite (int fd, char *buf, unsigned int len)
{
    int w = 0;

    w = timeoutwrite (60, fd, buf, len);
    if (w <= 0)
        errx (-1, "could not write to network");

    return w;
}

char netwritespace[1024];
buffer netwrite = BUFFER_INIT (safewrite, 1,
                               netwritespace, sizeof netwritespace);

void
print (char *buf, unsigned int len)
{
    char tcpheader[2];

    uint16_pack_big (tcpheader, len);
    buffer_put (&netwrite, tcpheader, 2);
    buffer_put (&netwrite, buf, len);
    buffer_flush (&netwrite);
}

char *axfr = NULL;
static char *axfrok = NULL;

void
axfrcheck (char *q)
{
    int i = 0, j = 0;

    if (!axfr)
        return;

    for (;;)
    {
        if (!axfr[i] || (axfr[i] == '/'))
        {
            if (i > j)
            {
                if (!dns_domain_fromdot (&axfrok, axfr + j, i - j))
                    err (-1, "could not allocate enough memory");
                if (dns_domain_equal (q, axfrok))
                    return;
            }
            j = i + 1;
        }
        if (!axfr[i])
            break;
        ++i;
    }

    err (-1, "zone transfer request not allowed");
}


char typeclass[4];
static char *zone;
unsigned int zonelen;

int fdcdb;
buffer bcdb;
char bcdbspace[1024];

void
get (char *buf, unsigned int len)
{
    int r = 0;

    while (len > 0)
    {
        r = buffer_get (&bcdb, buf, len);
        if (r < 0)
            err (-1, "could not read from file `data.cdb'");
        if (!r)
            err (-1, "could not read from file `data.cdb': format error");
        buf += r;
        len -= r;
    }
}

char ip[4];
char clientloc[2];
unsigned long port;

struct tai now;
char data[32767];
uint32 dlen = 0, dpos = 0;


void
copy (char *buf, unsigned int len)
{
    dpos = dns_packet_copy (data, dlen, dpos, buf, len);
    if (!dpos)
        err (-1, "could not read from file `data.cdb'");
}

void
doname (stralloc *sa)
{
    static char *d = NULL;

    dpos = dns_packet_getname (data, dlen, dpos, &d);
    if (!dpos)
        err (-1, "could not read from file `data.cdb'");
    if (!stralloc_catb (sa, d, dns_domain_length (d)))
        err (-1, "could not allocate enough memory");
}

int
build (stralloc *sa, char *q, int flagsoa, char id[2])
{
    char ttl[4];
    char ttd[8];
    char type[2];
    char misc[20];
    char recordloc[2];
    struct tai cutoff;
    unsigned int rdatapos = 0;

    dpos = 0;
    copy (type, 2);
    if (flagsoa)
        if (byte_diff (type, 2, DNS_T_SOA))
            return 0;

    if (!flagsoa)
        if (byte_equal (type, 2, DNS_T_SOA))
            return 0;

    if (!stralloc_copyb (sa, id, 2))
        err (-1, "could not allocate enough memory");
    if (!stralloc_catb (sa, "\204\000\0\0\0\1\0\0\0\0", 10))
        err (-1, "could not allocate enough memory");
    copy (misc, 1);

    if ((misc[0] == '=' + 1) || (misc[0] == '*' + 1))
    {
        --misc[0];
        copy (recordloc, 2);
        if (byte_diff (recordloc, 2, clientloc))
            return 0;
    }
    if (misc[0] == '*')
    {
        if (flagsoa)
            return 0;
        if (!stralloc_catb (sa, "\1*", 2))
            err (-1, "could not allocate enough memory");
    }
    if (!stralloc_catb (sa, q, dns_domain_length (q)))
        err (-1, "could not allocate enough memory");
    if (!stralloc_catb (sa, type, 2))
        err (-1, "could not allocate enough memory");

    copy (ttl, 4);
    copy (ttd, 8);
    if (byte_diff (ttd, 8, "\0\0\0\0\0\0\0\0"))
    {
        tai_unpack (ttd, &cutoff);
        if (byte_equal (ttl, 4, "\0\0\0\0"))
        {
            if (tai_less (&cutoff, &now))
                return 0;
            uint32_pack_big (ttl, 2);
        }
        else
            if (!tai_less (&cutoff, &now))
                return 0;
    }

    if (!stralloc_catb (sa, DNS_C_IN, 2))
        err (-1, "could not allocate enough memory");
    if (!stralloc_catb (sa, ttl, 4))
        err (-1, "could not allocate enough memory");
    if (!stralloc_catb(sa,"\0\0",2))
        err (-1, "could not allocate enough memory");
    rdatapos = sa->len;

    if (byte_equal (type, 2, DNS_T_SOA))
    {
        doname (sa);
        doname (sa);
        copy (misc, 20);
        if (!stralloc_catb (sa, misc, 20))
            err (-1, "could not allocate enough memory");
    }
    else if (byte_equal (type, 2, DNS_T_NS)
             || byte_equal (type, 2, DNS_T_PTR)
             || byte_equal (type, 2, DNS_T_CNAME))
    {
        doname (sa);
    }
    else if (byte_equal (type, 2, DNS_T_MX))
    {
        copy (misc, 2);
        if (!stralloc_catb (sa, misc, 2))
            err (-1, "could not allocate enough memory");
        doname (sa);
    }
    else
    {
        if (!stralloc_catb (sa, data + dpos, dlen - dpos))
            err (-1, "could not allocate enough memory");
    }

    if (sa->len > 65535)
        errx (-1, "could not read from file `data.cdb': format error");
    uint16_pack_big (sa->s + rdatapos - 2, sa->len - rdatapos);

    return 1;
}

static struct cdb c;
static char *q = NULL;

static stralloc soa;
static stralloc message;

void
doaxfr (char id[2])
{
    int r = 0;
    char num[4];
    char key[512];
    uint32 klen = 0;
    uint32 eod = 0, pos = 0;

    axfrcheck (zone);

    tai_now (&now);
    cdb_init (&c, fdcdb);

    byte_zero (clientloc, 2);
    key[0] = 0;
    key[1] = '%';
    byte_copy (key + 2, 4, ip);
    r = cdb_find (&c, key, 6);

    if (!r)
        r = cdb_find (&c, key, 5);
    if (!r)
        r = cdb_find (&c, key, 4);
    if (!r)
        r = cdb_find (&c, key, 3);
    if (!r)
        r = cdb_find (&c, key, 2);
    if (r == -1)
        errx (-1, "could not read from file `data.cdb'");
    if (r && (cdb_datalen (&c) == 2))
        if (cdb_read (&c, clientloc, 2, cdb_datapos (&c)) == -1)
            err (-1, "could not read from file `data.cdb'");

    cdb_findstart (&c);
    for (;;)
    {
        r = cdb_findnext (&c, zone, zonelen);
        if (r == -1)
            errx (-1, "could not read from file `data.cdb'");
        if (!r)
            errx (-1, "could not find information in `data.cdb'");
        dlen = cdb_datalen (&c);
        if (dlen > sizeof data)
            errx (-1, "could not read from file `data.cdb': format error");
        if (cdb_read (&c, data, dlen, cdb_datapos (&c)) == -1)
            errx (-1, "could not read from file `data.cdb': format error");
        if (build (&soa, zone, 1, id))
            break;
    }

    cdb_free (&c);
    print (soa.s, soa.len);

    seek_begin (fdcdb);
    buffer_init (&bcdb, buffer_unixread, fdcdb, bcdbspace, sizeof bcdbspace);

    pos = 0;
    get (num, 4);
    pos += 4;
    uint32_unpack (num, &eod);
    while (pos < 2048)
    {
        get (num, 4);
        pos += 4;
    }

    while (pos < eod)
    {
        if (eod - pos < 8)
            errx (-1, "could not read from file `data.cdb': format error");
        get (num, 4);
        pos += 4;
        uint32_unpack (num, &klen);
        get (num,4);
        pos += 4;
        uint32_unpack (num, &dlen);
        if (eod - pos < klen)
            errx (-1, "could not read from file `data.cdb': format error");
        pos += klen;
        if (eod - pos < dlen)
            errx (-1, "could not read from file `data.cdb': format error");
        pos += dlen;

        if (klen > sizeof key)
            errx (-1, "could not read from file `data.cdb': format error");
        get (key, klen);
        if (dlen > sizeof data)
            errx (-1, "could not read from file `data.cdb': format error");
        get (data, dlen);

        if ((klen > 1) && (key[0] == 0))
            continue; /* location */
        if (klen < 1)
            errx (-1, "could not read from file `data.cdb': format error");
        if (dns_packet_getname (key, klen, 0, &q) != klen)
            errx (-1, "could not read from file `data.cdb': format error");
        if (!dns_domain_suffix (q, zone))
            continue;
        if (!build (&message, q, 0, id))
            continue;
        print (message.s, message.len);
    }

    print (soa.s, soa.len);
}

void
netread (char *buf, unsigned int len)
{
    int r = 0;

    while (len > 0)
    {
        r = timeoutread (60, 0, buf, len);
        if (r == 0)
            exit (0);
        if (r < 0)
            err (-1, "could not read from the network");
        buf += r;
        len -= r;
    }
}

uint16 len;
char buf[512];
char tcpheader[2];

static char seed[128];

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
    printf ("%-17s %s\n", "    -d <value>", "print debug messages");
    printf ("%-17s %s\n", "    -D", "run as daemon");
    printf ("%-17s %s\n", "    -h --help", "print this help");
    printf ("%-17s %s\n", "    -v --version", "print version information");
    printf ("\nReport bugs to <pj.pandit@yahoo.co.in>\n");
}

int
check_option (int argc, char *argv[])
{
    int n = 0, ind = 0;
    const char optstr[] = "+:d:Dhv";
    struct option lopt[] = \
    {
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, 'v' },
        { 0, 0, 0, 0 }
    };

    opterr = optind = mode = 0;
    while ((n = getopt_long (argc, argv, optstr, lopt, &ind)) != -1)
    {
        switch (n)
        {
        case 'd':
            mode |= DEBUG;
            debug_level = atoi (optarg);
            break;

        case 'D':
            mode |= DAEMON;
            break;

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
    int n = 0;
    time_t t = 0;
    struct sigaction sa;

    char qtype[2];
    char qclass[2];
    char header[12];
    const char *x = NULL;
    unsigned int pos = 0;

    sa.sa_handler = handle_term;
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &sa, NULL);

    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ?  x + 1 : argv[0]);
    n = check_option (argc, argv);
    argc -= n;
    argv += n;

    if (mode & DAEMON)
    {
        n = fork ();
        if (n == -1)
            err (-1, "could not fork a daemon process");
        if (n > 0)
            return 0;
    }

    time (&t);
    memset (seed, 0, sizeof (seed));
    strftime (seed, sizeof (seed), "%b-%d %Y %T", localtime (&t));
    fprintf (stderr, "\n");
    warnx ("version %s: starting %s\n", VERSION, seed);
    memset (seed, 0, sizeof (seed));

    read_conf (CFGFILE);

    if (!debug_level)
        if ((x = env_get ("DEBUG_LEVEL")))
            debug_level = atol (x);
    warnx ("DEBUG_LEVEL set to `%d'", debug_level);

    dns_random_init (seed);

    axfr = env_get ("AXFR");
    x = env_get ("TCPREMOTEIP");
    if (x)
        ip4_scan (x, ip);
    else
        byte_zero (ip, 4);

    x = env_get ("TCPREMOTEPORT");
    if (!x)
        x = "0";
    scan_ulong (x, &port);

    droproot ();

    for (;;)
    {
        netread (tcpheader, 2);
        uint16_unpack_big (tcpheader, &len);
        if (len > 512)
            errx (-1, "excessively large request");
        netread (buf, len);

        pos = dns_packet_copy (buf, len, 0, header, 12);
        if (!pos)
            errx (-1, "truncated request");
        if (header[2] & 254)
            errx (-1, "bogus query");
        if (header[4] || (header[5] != 1))
            errx (-1, "bogus query");

        pos = dns_packet_getname (buf, len, pos, &zone);
        if (!pos)
            errx (-1, "truncated request");
        zonelen = dns_domain_length (zone);
        pos = dns_packet_copy (buf, len, pos, qtype, 2);
        if (!pos)
            errx (-1, "truncated request");
        pos = dns_packet_copy (buf, len, pos, qclass, 2);
        if (!pos)
            errx (-1, "truncated request");

        if (byte_diff(qclass, 2, DNS_C_IN) && byte_diff(qclass, 2, DNS_C_ANY))
            errx (-1, "bogus query: bad class");

        qlog (ip, port, header, zone, qtype, " ");
        if (byte_equal(qtype,2,DNS_T_AXFR))
        {
            case_lowerb (zone, zonelen);
            fdcdb = open_read ("data.cdb");
            if (fdcdb == -1)
                errx (-1, "could not read from file `data.cdb'");
            doaxfr (header);
            close (fdcdb);
        }
        else
        {
            if (!response_query (zone, qtype, qclass))
                err (-1, "could not allocate enough memory");
            response[2] |= 4;
            case_lowerb (zone, zonelen);
            response_id (header);
            response[3] &= ~128;
            if (!(header[2] & 1))
                response[2] &= ~1;
            if (!respond (zone, qtype, ip))
                errx (-1, "could not find information in file `data.cdb'");
            print (response, response_len);
        }
    }
}
