/*
 * dnscache.c: This file is part of the `djbdns' project, originally written
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

#define _GNU_SOURCE

#include <err.h>
#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/resource.h>

#include "version.h"

#define PIDFILE "/var/run/dnscache.pid"
#define LOGFILE "/var/log/dnscache.log"
#define CFGFILE SYSCONFDIR"/ndjbdns/dnscache.conf"

static char *prog = NULL;
short mode = 0, debug_level = 0;

#include "dns.h"
#include "env.h"
#include "ip4.h"
#include "fmt.h"
#include "log.h"
#include "scan.h"
#include "taia.h"
#include "byte.h"
#include "query.h"
#include "alloc.h"
#include "error.h"
#include "roots.h"
#include "cache.h"
#include "ndelay.h"
#include "strerr.h"
#include "uint16.h"
#include "uint64.h"
#include "socket.h"
#include "common.h"
#include "clients.h"
#include "iopause.h"
#include "response.h"
#include "okclient.h"
#include "droproot.h"

static int
packetquery (char *buf, unsigned int len, char **q,
                        char qtype[2], char qclass[2], char id[2])
{
    char header[12];
    unsigned int pos = 0;

    errno = error_proto;
    pos = dns_packet_copy (buf, len, 0, header, 12);
    if (!pos)
        return 0;
    if (header[2] & 128)
        return 0; /* must not respond to responses */
    if (!(header[2] & 1))
        return 0; /* do not respond to non-recursive queries */
    if (header[2] & 120)
        return 0;
    if (header[2] & 2)
        return 0;
    if (byte_diff (header + 4, 2, "\0\1"))
        return 0;

    pos = dns_packet_getname (buf, len, pos, q);
    if (!pos)
        return 0;
    pos = dns_packet_copy (buf, len, pos, qtype, 2);
    if (!pos)
        return 0;
    pos = dns_packet_copy (buf, len, pos, qclass, 2);
    if (!pos)
        return 0;
    if (byte_diff (qclass, 2, DNS_C_IN) && byte_diff (qclass, 2, DNS_C_ANY))
        return 0;

    byte_copy (id, 2, header);

    return 1;
}


uint64 numqueries = 0;
static char buf[1024];
static struct in_addr odst; /* original destination IP */
static char myipoutgoing[4];
static char myipincoming[4];

static int udp53 = 0;
static struct udpclient
{
    struct query q;
    struct taia start;
    uint64 active; /* query number, if active; otherwise 0 */
    iopause_fd *io;
    char ip[4];
    uint16 port;
    char id[2];
} u[MAXUDP];

int uactive = 0;

void
u_drop (int j)
{
    if (!u[j].active)
        return;

    if (debug_level > 2)
        log_querydrop (&u[j].active);

    u[j].active = 0;
    --uactive;
}

void
u_respond (int j)
{
    if (!u[j].active)
        return;

    response_id (u[j].id);
    if (response_len > 512)
        response_tc ();
    socket_send4 (udp53, response, response_len, u[j].ip, u[j].port, &odst);

    if (debug_level)
        log_querydone (&u[j].active, response, response_len);

    u[j].active = 0;
    --uactive;
}

void
u_new (void)
{
    int i = 0, j = 0, len = 0;
    struct udpclient *x = NULL;

    static char *q = 0;
    char qtype[2], qclass[2];

    for (j = 0; j < MAXUDP; j++)
        if (!u[j].active)
            break;

    if (j >= MAXUDP)
    {
        j = 0;
        for (i = 1; i < MAXUDP; i++)
            if (taia_less (&u[i].start, &u[j].start))
                j = i;
        errno = error_timeout;
        u_drop (j);
    }

    x = u + j;
    taia_now (&x->start);

    len = socket_recv4 (udp53, buf, sizeof (buf), x->ip, &x->port, &odst);
    if (len == -1)
        return;
    if ((unsigned)len >= sizeof buf)
        return;
    if (x->port < 1024 && x->port != 53)
        return;
    if (!okclient (x->ip))
        return;
    if (!packetquery (buf, len, &q, qtype, qclass, x->id))
        return;

    x->active = ++numqueries;
    ++uactive;

    if (debug_level)
        log_query (&x->active, x->ip, x->port, x->id, q, qtype);

    switch (query_start (&x->q, q, qtype, qclass, myipoutgoing))
    {
    case -1:
        u_drop (j);
        return;

    case 1:
        u_respond (j);
    }
}

static int tcp53 = 0;
struct tcpclient
{
    struct query q;
    struct taia start;
    struct taia timeout;
    uint64 active;  /* query number or 1, if active; otherwise 0 */
    iopause_fd *io;
    char ip[4];     /* send response to this address */
    uint16 port;    /* send response to this port */
    char id[2];
    int tcp;        /* open TCP socket, if active */
    int state;
    char *buf;      /* 0, or dynamically allocated of length len */
    unsigned int len;
    unsigned int pos;
} t[MAXTCP];

int tactive = 0;

/*
 * state 1: buf 0; normal state at beginning of TCP connection
 * state 2: buf 0; have read 1 byte of query packet length into len
 * state 3: buf allocated; have read pos bytes of buf
 * state 0: buf 0; handling query in q
 * state -1: buf allocated; have written pos bytes
 */

void
t_free (int j)
{
    if (!t[j].buf)
        return;

    alloc_free (t[j].buf);
    t[j].buf = 0;
}

void
t_timeout (int j)
{
    struct taia now;

    if (!t[j].active)
      return;

    taia_now (&now);
    taia_uint (&t[j].timeout, 10);
    taia_add (&t[j].timeout, &t[j].timeout, &now);
}

void
t_close (int j)
{
    if (!t[j].active)
      return;

    t_free (j);
    if (debug_level > 2)
        log_tcpclose (t[j].ip, t[j].port);

    close (t[j].tcp);
    t[j].active = 0;
    --tactive;
}

void
t_drop (int j)
{
    if (debug_level > 2)
        log_querydrop (&t[j].active);

    errno = error_pipe;
    t_close (j);
}

void
t_respond (int j)
{
    if (!t[j].active)
        return;

    if (debug_level)
        log_querydone (&t[j].active, response, response_len);

    response_id (t[j].id);
    t[j].len = response_len + 2;
    t_free (j);
    t[j].buf = alloc (response_len + 2);
    if (!t[j].buf)
    {
        t_close (j);
        return;
    }
    uint16_pack_big (t[j].buf, response_len);
    byte_copy (t[j].buf + 2, response_len, response);
    t[j].pos = 0;
    t[j].state = -1;
}

void
t_rw (int j)
{
    int r;
    char ch;
    static char *q = 0;
    char qtype[2], qclass[2];
    struct tcpclient *x = NULL;

    x = t + j;
    if (x->state == -1)
    {
        r = write (x->tcp, x->buf + x->pos, x->len - x->pos);
        if (r <= 0)
        {
            t_close (j);
            return;
        }
        x->pos += r;
        if (x->pos == x->len)
        {
            t_free (j);
            x->state = 1; /* could drop connection immediately */
        }
        return;
    }

    r = read (x->tcp, &ch, 1);
    if (r == 0)
    {
        errno = error_pipe;
        t_close (j);
        return;
    }
    if (r < 0)
    {
        t_close (j);
        return;
    }

    if (x->state == 1)
    {
        x->len = (unsigned char)ch;
        x->len <<= 8;
        x->state = 2;
        return;
    }
    if (x->state == 2)
    {
        x->len += (unsigned char)ch;
        if (!x->len)
        {
            errno = error_proto;
            t_close (j);
            return;
        }
        x->buf = alloc (x->len);
        if (!x->buf)
        {
            t_close(j);
            return;
        }
        x->pos = 0;
        x->state = 3;

        return;
    }

    if (x->state != 3)
        return; /* impossible */

    x->buf[x->pos++] = ch;
    if (x->pos < x->len)
        return;

    if (!packetquery (x->buf, x->len, &q, qtype, qclass, x->id))
    {
        t_close(j);
        return;
    }

    x->active = ++numqueries;

    if (debug_level)
        log_query (&x->active, x->ip, x->port, x->id, q, qtype);

    switch (query_start (&x->q, q, qtype, qclass, myipoutgoing))
    {
    case -1:
        t_drop (j);
        return;
    case 1:
        t_respond (j);
        return;
    }
    t_free (j);
    x->state = 0;
}

void
t_new (void)
{
    int i = 0, j = 0;
    struct tcpclient *x = NULL;

    for (j = 0; j < MAXTCP; ++j)
        if (!t[j].active)
          break;

    if (j >= MAXTCP)
    {
        j = 0;
        for (i = 1; i < MAXTCP; ++i)
            if (taia_less (&t[i].start, &t[j].start))
                j = i;
        errno = error_timeout;
        if (t[j].state == 0)
          t_drop (j);
        else
          t_close (j);
    }

    x = t + j;
    taia_now (&x->start);

    x->tcp = socket_accept4 (tcp53, x->ip, &x->port);
    if (x->tcp == -1)
        return;
    if (x->port < 1024 && x->port != 53)
    {
        close (x->tcp);
        return;
    }
    if (!okclient (x->ip))
    {
        close (x->tcp);
        return;
    }
    if (ndelay_on (x->tcp) == -1)
    {
        close(x->tcp);
        return;
    } /* Linux bug */

    x->active = 1;
    ++tactive;
    x->state = 1;
    t_timeout (j);

    if (debug_level > 2)
        log_tcpopen (x->ip, x->port);
}


iopause_fd *udp53io = NULL;
iopause_fd *tcp53io = NULL;
iopause_fd io[3 + MAXUDP + MAXTCP];


static void
doit (void)
{
    struct taia stamp;
    struct taia deadline;
    int j = 0, r = 0, iolen = 0;

    for (;;)
    {
        taia_now (&stamp);
        taia_uint (&deadline, 120);
        taia_add (&deadline, &deadline, &stamp);

        iolen = 0;
        udp53io = io + iolen++;
        udp53io->fd = udp53;
        udp53io->events = IOPAUSE_READ;

        tcp53io = io + iolen++;
        tcp53io->fd = tcp53;
        tcp53io->events = IOPAUSE_READ;

        for (j = 0; j < MAXUDP; ++j)
        {
            if (u[j].active)
            {
                u[j].io = io + iolen++;
                query_io (&u[j].q, u[j].io, &deadline);
            }
        }

        for (j = 0; j < MAXTCP; ++j)
        {
            if (t[j].active)
            {
                t[j].io = io + iolen++;
                if (t[j].state == 0)
                    query_io (&t[j].q, t[j].io, &deadline);
                else
                {
                    if (taia_less (&t[j].timeout, &deadline))
                        deadline = t[j].timeout;
                    t[j].io->fd = t[j].tcp;
                    t[j].io->events = (t[j].state > 0) ?
                                            IOPAUSE_READ : IOPAUSE_WRITE;
                }
            }
        }
        iopause (io, iolen, &deadline, &stamp);

        for (j = 0; j < MAXUDP; ++j)
        {
            if (u[j].active)
            {
                r = query_get (&u[j].q, u[j].io, &stamp);
                if (r == -1)
                    u_drop (j);
                if (r == 1)
                    u_respond (j);
            }
        }
        for (j = 0; j < MAXTCP; ++j)
        {
            if (t[j].active)
            {
                if (t[j].io->revents)
                    t_timeout (j);
                if (t[j].state == 0)
                {
                    r = query_get (&t[j].q, t[j].io, &stamp);
                    if (r == -1)
                        t_drop (j);
                    if (r == 1)
                        t_respond (j);
                }
                else
                    if (t[j].io->revents || taia_less (&t[j].timeout, &stamp))
                        t_rw (j);
            }
        }

        if (udp53io && udp53io->revents)
                u_new();

        if (tcp53io && tcp53io->revents)
                t_new();
    }
}


extern uint32 seed[32];         /* defined in common.c */

void
usage (void)
{
    printf ("Usage: %s [OPTIONS]\n", prog);
}

void
printh (void)
{
    usage ();
    printf ("\n Options: \n");
    printf ("%-17s %s\n", "   -d <value>", "print debug messages");
    printf ("%-17s %s\n", "   -D", "run as daemon");
    printf ("%-17s %s\n", "   -h --help", "print this help");
    printf ("%-17s %s\n", "   -v --version", "print version information");
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
            printf ("%s version %s\n", prog, VERSION);
            exit (0);

        case ':':
            errx (-1, "option `%c' takes an argument, see: --help", optopt);

        default:
            errx (-1, "unknown option `%c', see: --help", optopt);
        }
    }

    return optind;
}


int
main (int argc, char *argv[])
{
    int i = 0;
    time_t t = 0;
    struct sigaction sa;
    unsigned long cachesize = 0;
    char *x = NULL, char_seed[128];

    sa.sa_handler = handle_term;
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &sa, NULL);

    seed_addtime ();
    seed_adduint32 (getpid ());
    seed_adduint32 (getppid ());
    seed_adduint32 (getuid ());
    seed_adduint32 (getgid ());

    seed_addtime ();
    prog = strdup ((x = strrchr (argv[0], '/')) != NULL ?  x + 1 : argv[0]);
    i = check_option (argc, argv);
    argc -= i;
    argv += i;

    if (mode & DAEMON)
    {
        i = fork ();
        if (i == -1)
            err (-1, "could not fork a daemon process");
        if (i > 0)
            return 0;
    }

    time (&t);
    strftime (char_seed, sizeof (char_seed), "%b-%d %Y %T %Z", localtime (&t));
    warnx ("version %s: starting: %s\n", VERSION, char_seed);

    set_timezone ();
    if (debug_level)
        warnx ("TIMEZONE: %s", env_get ("TZ"));

    read_conf (CFGFILE);
    if (!debug_level)
        if ((x = env_get ("DEBUG_LEVEL")))
            debug_level = atol (x);
    warnx ("DEBUG_LEVEL set to `%d'", debug_level);

    if ((x = env_get ("DATALIMIT")))
    {
        struct rlimit r;
        unsigned long dlimit = atol (x);

        if (getrlimit (RLIMIT_DATA,  &r) != 0)
            err (-1, "could not get resource RLIMIT_DATA");

        r.rlim_cur = (dlimit <= r.rlim_max) ? dlimit : r.rlim_max;

        if (setrlimit (RLIMIT_DATA, &r) != 0)
            err (-1, "could not set resource RLIMIT_DATA");

        if (debug_level)
            warnx ("DATALIMIT set to `%ld' bytes", r.rlim_cur);
    }

    if (!(x = env_get ("IP")))
        err (-1, "$IP not set");
    if (!ip4_scan (x, myipincoming))
        err (-1, "could not parse IP address `%s'", x);

    seed_addtime ();
    udp53 = socket_udp ();
    if (udp53 == -1)
        err (-1, "could not open UDP socket");
    if (socket_bind4_reuse (udp53, myipincoming, 53) == -1)
        err (-1, "could not bind UDP socket");

    seed_addtime ();
    tcp53 = socket_tcp ();
    if (tcp53 == -1)
        err (-1, "could not open TCP socket");
    if (socket_bind4_reuse (tcp53, myipincoming, 53) == -1)
        err (-1, "could not bind TCP socket");

    if (mode & DAEMON)
    {
        /* redirect stdout & stderr to a log file */
        redirect_to_log (LOGFILE);

        write_pid (PIDFILE);
    }

    seed_addtime ();
    droproot ();
    if (mode & DAEMON)
        /* crerate a new session & detach from controlling tty */
        if (setsid () < 0)
            err (-1, "could not start a new session for the daemon");

    seed_addtime ();
    socket_tryreservein (udp53, 131072);

    memset (char_seed, 0, sizeof (char_seed));
    for (i = 0, x = (char *)seed; (unsigned)i < sizeof (char_seed); i++, x++)
        char_seed[i] = *x;
    dns_random_init (char_seed);

    if (!(x = env_get ("IPSEND")))
        err (-1, "$IPSEND not set");
    if (!ip4_scan (x, myipoutgoing))
        err (-1, "could not parse IP address `%s'", x);

    if (!(x = env_get ("CACHESIZE")))
        err (-1, "$CACHESIZE not set");
    scan_ulong (x, &cachesize);
    if (!cache_init (cachesize))
        err (-1, "could not allocate `%ld' bytes for cache", cachesize);

    if (env_get ("HIDETTL"))
        response_hidettl ();
    if (env_get ("FORWARDONLY"))
        query_forwardonly ();
    if (env_get ("MERGEQUERIES"))
        dns_enable_merge (log_merge);
    if (!roots_init ())
        err (-1, "could not read servers");
    if (debug_level > 3)
        roots_display();
    if (socket_listen (tcp53, 20) == -1)
        err (-1, "could not listen on TCP socket");

    doit ();

    return 0;
}
