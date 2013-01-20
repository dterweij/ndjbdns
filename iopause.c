/*
 * iopause.c: This file is part of the `djbdns' project, originally written
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

#include "taia.h"
#include "select.h"
#include "iopause.h"

void
iopause (iopause_fd *x, unsigned int len,
                        struct taia *deadline, struct taia *stamp)
{
    double d = 0;
    struct taia t;
    int i = 0, millisecs = 0;

    if (taia_less (deadline, stamp))
        millisecs = 0;
    else
    {
        t = *stamp;
        taia_sub (&t, deadline, &t);
        d = taia_approx (&t);
        if (d > 1000.0)
            d = 1000.0;
        millisecs = d * 1000.0 + 20.0;
    }

    for (i = 0; (unsigned)i < len; ++i)
        x[i].revents = 0;

#ifdef IOPAUSE_POLL

    poll(x, len, millisecs);
    /* XXX: some kernels apparently need x[0] even if len is 0 */
    /* XXX: how to handle EAGAIN? are kernels really this dumb? */
    /* XXX: how to handle EINVAL? when exactly can this happen? */

#else

    struct timeval tv;
    fd_set rfds, wfds;
    int nfds = 0, fd = 0;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    nfds = 1;
    for (i = 0; i < len; ++i)
    {
        fd = x[i].fd;
        if (fd < 0)
            continue;
        if (fd >= 8 * sizeof (fd_set))
            continue; /*XXX*/

        if (fd >= nfds)
            nfds = fd + 1;
        if (x[i].events & IOPAUSE_READ)
            FD_SET (fd,&rfds);
        if (x[i].events & IOPAUSE_WRITE)
            FD_SET (fd,&wfds);
    }

    tv.tv_sec = millisecs / 1000;
    tv.tv_usec = 1000 * (millisecs % 1000);

    if (select (nfds, &rfds, &wfds, (fd_set *)0, &tv) <= 0)
        return;
    /* XXX: for EBADF, could seek out and destroy the bad descriptor */

    for (i = 0; i < len; ++i)
    {
        fd = x[i].fd;
        if (fd < 0)
            continue;
        if (fd >= 8 * sizeof (fd_set))
            continue; /*XXX*/

        if (x[i].events & IOPAUSE_READ)
          if (FD_ISSET (fd, &rfds))
              x[i].revents |= IOPAUSE_READ;

        if (x[i].events & IOPAUSE_WRITE)
          if (FD_ISSET (fd, &wfds))
              x[i].revents |= IOPAUSE_WRITE;
    }

#endif

}
