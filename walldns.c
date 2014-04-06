/*
 * walldns.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * Copyright (C) 2009 - 2014 Prasad J Pandit
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

#include <unistd.h>

#include "dd.h"
#include "dns.h"
#include "byte.h"
#include "common.h"
#include "response.h"

#define PIDFILE "/var/run/walldns.pid"
#define LOGFILE "/var/log/walldns.log"
#define CFGFILE SYSCONFDIR"/ndjbdns/walldns.conf"

extern short mode;
extern char *cfgfile, *logfile, *pidfile;

void
initialize (void)
{
    cfgfile = cfgfile ? cfgfile : CFGFILE;
    logfile = logfile ? logfile : LOGFILE;
    pidfile = pidfile ? pidfile : PIDFILE;

    read_conf (cfgfile);
    if (mode & DAEMON)
    {
        /* redirect stdout & stderr to a log file */
        redirect_to_log (logfile, STDOUT_FILENO | STDERR_FILENO);
        write_pid (pidfile);
    }
}

int
respond (char *q, char qtype[2])
{
    int j = 0;
    char ip[4];
    int flaga = 0;
    int flagptr = 0;

    flaga = byte_equal (qtype, 2, DNS_T_A);
    flagptr = byte_equal (qtype, 2, DNS_T_PTR);
    if (byte_equal (qtype, 2, DNS_T_ANY))
        flaga = flagptr = 1;

    if (flaga || flagptr)
    {
        if (dd (q, "", ip) == 4)
        {
            if (flaga)
            {
                if (!response_rstart (q, DNS_T_A, 655360))
                    return 0;
                if (!response_addbytes (ip, 4))
                    return 0;
                response_rfinish (RESPONSE_ANSWER);
            }
            return 1;
        }
        j = dd (q, "\7in-addr\4arpa", ip);
        if (j >= 0)
        {
            if (flaga && (j == 4))
            {
                if (!response_rstart (q, DNS_T_A, 655360))
                    return 0;
                if (!response_addbytes (ip + 3, 1))
                    return 0;
                if (!response_addbytes (ip + 2, 1))
                    return 0;
                if (!response_addbytes (ip + 1, 1))
                    return 0;
                if (!response_addbytes (ip + 0, 1))
                    return 0;
                response_rfinish (RESPONSE_ANSWER);
            }
            if (flagptr)
            {
                if (!response_rstart (q, DNS_T_PTR, 655360))
                    return 0;
                if (!response_addname (q))
                    return 0;
                response_rfinish (RESPONSE_ANSWER);
            }
            return 1;
        }
    }

    response[2] &= ~4;
    response[3] &= ~15;
    response[3] |= 5;
    return 1;
}
