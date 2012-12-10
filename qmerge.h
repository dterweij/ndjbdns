/*
 * qmerge.h: This file is part of the `ndjbdns' project. Originally written
 * by Mr Jeff King <peff@peff.net> as part of a patch to merge outgoing
 * queries and released under public-domain -> http://www.your.org/dnscache/
 *
 * Copyright (C) 2012 Prasad J Pandit
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

#ifndef QMERGE_H
#define QMERGE_H

#include "dns.h"

struct qmerge_key
{
    char *q;
    char qtype[2];
    char *control;
};

struct qmerge
{
    int active;
    struct qmerge_key key;
    struct dns_transmit dt;
    int state; /* -1 = error, 0 = need io, 1 = need get, 2 = got packet */
};

extern int qmerge_start(struct qmerge **, const char *, int, const char *,
                        const char *, const char *, const char *);

extern void qmerge_io(struct qmerge *, iopause_fd *, struct taia *);

extern int qmerge_get(struct qmerge **, const iopause_fd *,
                                        const struct taia *);

extern void qmerge_free(struct qmerge **);

#endif /* QMERGE_H */
