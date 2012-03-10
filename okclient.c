/*
 * okclient.c: This file is part of the `djbdns' project, originally written
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

#include <sys/stat.h>
#include <sys/types.h>

#include "str.h"
#include "ip4.h"
#include "okclient.h"

static char fn[3 + IP4_FMT];        /* ip4.h: IP4_FMT = 20 */

int
okclient (char ip[4])
{
    int i = 0;
    struct stat st;

    fn[0] = 'i';
    fn[1] = 'p';
    fn[2] = '/';
    fn[3 + ip4_fmt (fn + 3, ip)] = 0;

    for (;;)
    {
        if (stat (fn, &st) == 0)
            return 1;

        /* treat temporary error as rejection */
        i = str_rchr (fn, '.');
        if (!fn[i])
            return 0;

        fn[i] = 0;
    }
}
