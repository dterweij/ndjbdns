/*
 * prot.c: This file is part of the `djbdns' project, originally written
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

#include <grp.h>
#include <unistd.h>

#include "prot.h"
#include "hasshsgr.h"

int
prot_gid (gid_t gid)
{
#ifdef HASSHORTSETGROUPS
    short x[2];
    x[0] = gid;
    x[1] = 73; /* catch errors */
    if (setgroups (1, x) == -1)
        return -1;
#else
    if (setgroups(1, &gid) == -1)
        return -1;
#endif

  if (setgid (gid) == -1)
      return -1;

  return setegid (gid); /* _should_ be redundant; On some systems it isn't */
}

int
prot_uid (uid_t uid)
{
    if (setuid (uid) == -1)
        return -1;

    return seteuid (uid);
}
