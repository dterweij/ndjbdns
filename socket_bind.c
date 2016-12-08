/*
 * socket_bind.c: This file is part of the `djbdns' project, originally
 * written by Dr. D J Bernstein and later released under public-domain
 * since late December 2007 (http://cr.yp.to/distributors.html).
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "byte.h"
#include "socket.h"

int
socket_bind4 (int s, char ip[4], uint16 port)
{
    int opt = 1;
    struct sockaddr_in sa;

    byte_zero(&sa, sizeof (sa));
    sa.sin_family = AF_INET;

    uint16_pack_big ((char *)&sa.sin_port, port);
    byte_copy ((char *)&sa.sin_addr, 4, ip);

#ifdef IP_PKTINFO
    setsockopt (s, IPPROTO_IP, IP_PKTINFO, &opt, sizeof (opt));
#elif defined IP_RECVDSTADDR
    setsockopt (s, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof (opt));
#endif

    return bind (s, (struct sockaddr *)&sa, sizeof (sa));
}

int
socket_bind4_reuse (int s, char ip[4], uint16 port)
{
    int opt = 1;

    setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

    return socket_bind4 (s, ip, port);
}

void
socket_tryreservein (int s, int size)
{
    while (size >= 1024)
    {
        if (!setsockopt (s, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size)))
            return;
        size -= (size >> 5);
    }
}
