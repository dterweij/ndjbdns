/*
 * droproot.c: This file is part of the `djbdns' project, originally written
 * by Dr. D J Bernstein and later released under public-domain since late
 * December 2007 (http://cr.yp.to/distributors.html).
 *
 * I've modified this file for good and am releasing this new version under
 * GNU General Public License.
 * Copyright (C) 2009 - 2011 Prasad J Pandit
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


#include <err.h>
#include <unistd.h>

#include "env.h"
#include "scan.h"
#include "prot.h"
#include "strerr.h"

extern short debug_level;

void
droproot (void)
{
    char *x = NULL;
    unsigned long id = 0;

    x = env_get ("ROOT");
    if (!x)
        err (-1, "$ROOT not set");
    if (chdir (x) == -1)
        err (-1, "could not change working directory to `%s'", x);
    if (chroot(".") == -1)
        err (-1, "could not change root directory to `%s'", x);

    if (debug_level)
        warnx ("root & working directory changed to `%s'", x);

    x = env_get ("GID");
    if (!x)
        err (-1, "$GID not set");
    scan_ulong (x, &id);
    if (prot_gid ((int) id) == -1)
        err (-1, "could not set group-id to `%ld'", id);

    x = env_get ("UID");
    if (!x)
        err (-1, "$UID not set");
    scan_ulong (x, &id);
    if (prot_uid ((int) id) == -1)
        err (-1, "could not set user-id to `%ld'", id);

    if (debug_level)
        warnx ("root privileges dropped, user-id set to `%ld'", id);
}
