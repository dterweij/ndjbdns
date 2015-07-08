/*
 * socket_send.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
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

#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "byte.h"
#include "socket.h"

int
socket_send4 (int s, char *buf, int len,
                const char ip[4], uint16 port, void *src)
{
    char cbuf[256];
    struct iovec iov;
    struct msghdr msgh;
    struct sockaddr_in sa;
    struct cmsghdr *cmsg = NULL;

    byte_zero (&sa, sizeof (sa));
    sa.sin_family = AF_INET;

    uint16_pack_big ((char *)&sa.sin_port, port);
    byte_copy ((char *)&sa.sin_addr, 4, ip);

    memset (cbuf, 0, sizeof (cbuf));
    memset (&msgh, 0, sizeof (msgh));

    iov.iov_len = len;
    iov.iov_base = buf;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    msgh.msg_name = &sa;
    msgh.msg_namelen = sizeof (sa);

#ifdef IP_PKTINFO
    struct in_pktinfo *p = NULL;

    msgh.msg_control = cbuf;
    msgh.msg_controllen = CMSG_SPACE (sizeof (*p));

    cmsg = CMSG_FIRSTHDR (&msgh);
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_len = CMSG_LEN (sizeof (*p));

    p = (struct in_pktinfo *) CMSG_DATA (cmsg);
#ifndef __CYGWIN__
    p->ipi_spec_dst = *(struct in_addr *)src;
#endif
#elif defined IP_SENDSRCADDR
    struct in_addr *p = NULL;

    msgh.msg_control = cbuf;
    msgh.msg_controllen = CMSG_SPACE (sizeof (*p));

    cmsg = CMSG_FIRSTHDR (&msgh);
    cmsg->cmsg_type = IP_SENDSRCADDR;
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_len = CMSG_LEN (sizeof (*p));

    p = (struct in_addr *)CMSG_DATA (cmsg);
    p->s_addr = *(struct in_addr *)src;
#endif

    msgh.msg_flags = 0;
    msgh.msg_controllen = cmsg ? cmsg->cmsg_len : 0;
    return sendmsg (s, &msgh, 0);
}
