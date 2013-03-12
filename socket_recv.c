/*
 * socket_recv.c: This file is part of the `djbdns' project, originally
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

#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "byte.h"
#include "socket.h"

/* socket_dest_ip: retrieves destination IP address from a received packet.
 * This is useful on multi-home machines, wherein a server listens on the
 * common address: 0.0.0.0. Returned is an IP address to which received
 * packet was destined.
 */
static struct in_addr
socket_dest_ip (struct msghdr *msgh)
{
    struct in_addr odst = {0};
    struct cmsghdr *cmsg = NULL;

    for (cmsg = CMSG_FIRSTHDR (msgh);
            cmsg != NULL; cmsg = CMSG_NXTHDR (msgh, cmsg))
    {
#ifdef IP_PKTINFO
        if ((cmsg->cmsg_level == IPPROTO_IP)
            && (cmsg->cmsg_type == IP_PKTINFO))
        {
            struct in_pktinfo *p = (struct in_pktinfo *)CMSG_DATA (cmsg);
            odst = p->ipi_addr;
            break;
        }
#elif defined IP_RECVDSTADDR
        if ((cmsg->cmsg_level == IPPROTO_IP)
            && (cmsg->cmsg_type == IP_RECVDSTADDR))
        {
            struct in_addr *p = (struct in_addr *)CMSG_DATA (cmsg);
            odst = *p;
            break;
        }
#endif
    }

    return odst;
}

int
socket_recv4 (int s, char *buf, int len, char ip[4], uint16 *port, void *odst)
{
    int r = 0;
    char cbuf[256];
    struct iovec iov;
    struct msghdr msgh;
    struct sockaddr_in sa;
/*
    r = recvfrom (s, buf, len, 0, (struct sockaddr *)&sa, sizeof (sa));
    if (r == -1)
        return -1;
*/
    memset (buf, 0, len);
    memset (cbuf, 0, sizeof (cbuf));
    memset (&msgh, 0, sizeof (msgh));

    iov.iov_len = len;
    iov.iov_base = buf;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    msgh.msg_name = &sa;
    msgh.msg_namelen = sizeof (sa);

    msgh.msg_flags = 0;
    msgh.msg_control = cbuf;
    msgh.msg_controllen = sizeof (cbuf);

    r = recvmsg (s, &msgh, 0);
    if (r == -1)
        return r;

    byte_copy (ip, 4, (char *)&sa.sin_addr);
    uint16_unpack_big ((char *)&sa.sin_port, port);

    *(struct in_addr *)odst = socket_dest_ip (&msgh);
    return r;
}
