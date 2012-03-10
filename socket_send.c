/*
 * socket_send.c: This file is part of the `djbdns' project, originally written
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "byte.h"
#include "socket.h"

int
socket_send4 (int s, const char *buf, int len, const char ip[4], uint16 port)
{
    struct sockaddr_in sa;

    byte_zero (&sa, sizeof sa);
    sa.sin_family = AF_INET;
    uint16_pack_big ((char *)&sa.sin_port, port);
    byte_copy ((char *)&sa.sin_addr, 4, ip);

    return sendto (s, buf, len, 0, (struct sockaddr *)&sa, sizeof sa);
}
