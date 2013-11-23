/*
 * common.c: This file is part of the `djbdns' project, originally written
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "taia.h"
#include "uint16.h"
#include "uint32.h"
#include "uint64.h"
#include "buffer.h"

#define free(ptr)   free ((ptr)); (ptr) = NULL

extern short mode, debug_level;

#ifndef __USE_GNU

#include <sys/stat.h>

ssize_t
extend_buffer (char **buf)
{
    ssize_t n = 128;
    char *newbuf = NULL;

    if (*buf)
        n += strlen (*buf);

    if (!(newbuf = calloc (n, sizeof (char))))
        err (-1, "could not allocate enough memory");

    if (*buf)
    {
        strncpy (newbuf, *buf, n);
        free (*buf);
    }

    *buf = newbuf;
    return n;
}

size_t
getline (char **lineptr, ssize_t *n, FILE *stream)
{
    assert (stream != NULL);

    int i = 0, c = 0;
    char *buf = *lineptr;

    while ((c = fgetc (stream)) != EOF)
    {
        if (!buf || i + 1 == *n)
            *n = extend_buffer (&buf);

        buf[i++] = c;
        if (c == '\n' || c == '\0')
            break;
    }
    *lineptr = buf;

    if (c == EOF)
        i = -1;

    return i;
}

#endif      /* #ifndef __USE_GNU */


uint32 seed[32];
int seedpos = 0;

void
seed_adduint32 (uint32 u)
{
    int i = 0;

    seed[seedpos] += u;
    if (++seedpos == 32)
    {
        for (i = 0; i < 32; ++i)
        {
            u = ((u ^ seed[i]) + 0x9e3779b9) ^ (u << 7) ^ (u >> 25);
            seed[i] = u;
        }
        seedpos = 0;
    }
}

void
seed_addtime (void)
{
    int i = 0;
    struct taia t;
    char tpack[TAIA_PACK];

    taia_now (&t);
    taia_pack (tpack, &t);
    for (i = 0; i < TAIA_PACK; ++i)
        seed_adduint32 (tpack[i]);
}


/*
 * strtrim: removes leading & trailing white spaces(space, tab, new-line, etc)
 * from a given character string and returns a pointer to the new string.
 * Do free(3) it later.
 */
char *
strtrim (const char *s)
{
    if (s == NULL)
        return NULL;

    const char *e = &s[strlen(s) - 1];

    while (*s)
    {
        if (isspace (*s))
            s++;
        else
            break;
    }

    while (*e)
    {
        if (isspace (*e))
            e--;
        else
            break;
    }
    e++;

    return strndup (s, e - s);
}


/* checks if the given variable is valid & used by dnscache. */
int
check_variable (const char *var)
{
    assert (var != NULL);

    int i = 0, l = 0;
    const char *known_variable[] = \
    {
        "AXFR", "DATALIMIT", "CACHESIZE", "IP", "IPSEND",
        "UID", "GID", "ROOT", "HIDETTL", "FORWARDONLY",
        "MERGEQUERIES", "DEBUG_LEVEL", "BASE", "TCPREMOTEIP",
        "TCPREMOTEPORT"
    };

    l = sizeof (known_variable) / sizeof (*known_variable);
    for (i = 0; i < l; i++)
    {
        if (strlen (var) != strlen (known_variable[i]))
            continue;
        if (!memcmp (var, known_variable[i], strlen (var)))
            return 1;
    }

    return 0;
}


void
read_conf (const char *file)
{
    assert (file != NULL);

    int lcount = 0;
    FILE *fp = NULL;
    size_t l = 0, n = 0;
    char *line = NULL, *key = NULL, *val = NULL;

    if (!(fp = fopen (file, "r")))
        err (-1, "could not open file `%s'", file);

    while ((signed)(n = getline (&line, &l, fp)) != -1)
    {
        lcount++;
        line[n - 1] = '\0';
        char *s = strtrim (line);
        if (*s && *s != '#' && *s != '\n')
        {
            key = strtrim (strtok (s, "="));
            if (!check_variable (key))
                errx (-1, "%s: %d: unknown variable `%s'", file, lcount, key);

            val = strtrim (strtok (NULL, "="));
            if (debug_level)
                warnx ("%s: %s", key, val);

            if (val)
            {
                setenv (key, val, 1);
                free (val);
            }

            free (s);
            free (key);
            free (line);
        }
        seed_addtime ();
    }

    fclose (fp);
}

/* redirect stdout & stderr to a log file */
void
redirect_to_log (const char *logfile)
{
    assert (logfile != NULL);

    int fd = 0, perm = S_IRUSR | S_IWUSR;

    if ((fd = open (logfile, O_CREAT | O_WRONLY | O_APPEND, perm)) == -1)
        err (-1, "could not open logfile `%s'", logfile);

    if (dup2 (fd, STDOUT_FILENO) == -1)
        err (-1, "could not duplicate stdout");
    if (dup2 (fd, STDERR_FILENO) == -1)
        err (-1, "could not duplicate stderr");
}

/*
 * wirets pid to a file under /var/run directory, which will be used by
 * /sbin/service to shut down the dns daemon.
 */
void
write_pid (const char *pidfile)
{
    int n = 0, fd = 0, perm = 0;
    char *pid = strdup (pidfile);

    perm = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if ((fd = open (pid, O_CREAT | O_WRONLY | O_TRUNC, perm)) == -1)
        err (-1, "could not open file: `%s'", pid);

    memset (pid, '\0', strlen (pid));
    n = sprintf (pid, "%d\n", getpid ());
    write (fd, pid, n);

    close (fd);
    free (pid);
}

void
handle_term (int n)
{
    warnx ("going down with signal: %d ---\n", n);
    exit (0);
}

/*
 * set_timezone: set `TZ' environment variable to appropriate time zone value.
 * `TZ' environment variable is used by numerous - <time.h> - functions to
 * perform local time conversions. TZ: NAME[+-]HH:MM, ex: IST-5:30 etc.
 */
void
set_timezone (void)
{
    char tzone[12] = "";
    char hh = timezone / (60 * 60);
    char mm = abs (timezone % (60 * 60) / 60);

    tzset ();
    snprintf (tzone, sizeof (tzone), "%s%+d:%d", tzname[0], hh, mm);
    setenv ("TZ", tzone, 1);
}

void
number (uint64 u64)
{
    char buf[20];
    unsigned int pos = 0;

    pos = sizeof (buf);
    do
    {
        if (!pos)
            break;
        buf[--pos] = '0' + (u64 % 10);
        u64 /= 10;
    } while (u64);

    buffer_put (buffer_2, buf + pos, sizeof (buf) - pos);
}

void
string (const char *s)
{
    buffer_puts (buffer_2, s);
}

void
logid (const char id[2])
{
    uint16 u = 0;
    uint16_unpack_big (id, &u);

    number (u);
}

void
logtype (const char type[2])
{
    uint16 u = 0;
    char *qtype[] = {
        "\0",
        "A",        /* 1 a host address */
        "NS",       /* 2 an authoritative name server */
        "MD",       /* 3 a mail destination (obsolete, use MX) */
        "MF",       /* 4 a mail forwarder (obsolete, use MX) */
        "CNAME",    /* 5 the canonical name for an alias */
        "SOA",      /* 6 marks the start of a zone authority */
        "MB",       /* 7 a mailbox domain name (experimental) */
        "MG",       /* 8 a mail group member (experimental) */
        "MR",       /* 9 a mail rename domain name (experimental) */
        "NULL",     /*10 a NULL RR (experimental) */
        "WKS",      /*11 a well known service description */
        "PTR",      /*12 a domain name pointer */
        "HINFO",    /*13 host information */
        "MINFO",    /*14 mailbox or mail list information */
        "MX",       /*15 mail exchange */
        "TXT",      /*16 text strings */
        "AAAA",     /*17  28 IPv6 host address */
        "AXFR",     /*18 252 transfer of an entire zone */
        "MAILB",    /*19 253 mailbox-related records MB, MG or MR */
        "MAILA",    /*20 254 mail agent RRs (obsolete, use MX) */
        "*",        /*21 255 requst for all records*/
    };

    uint16_unpack_big (type, &u);
    u = (u < 17) ? u : (u == 28) ? 17 : (u > 251 && u < 256) ? u - 234 : u;
    if (u < (sizeof (qtype) / sizeof (char *)))
        string(qtype[u]);
    else
        number (u);
}
