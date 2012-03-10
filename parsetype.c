/*
 * parsetype.c: This file is part of the `djbdns' project, originally written
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

#include "scan.h"
#include "byte.h"
#include "case.h"
#include "dns.h"
#include "uint16.h"
#include "parsetype.h"

int
parsetype (char *s, char type[2])
{
    unsigned long u = 0;

    if (!s[scan_ulong (s, &u)])
        uint16_pack_big (type, u);
    else if (case_equals (s, "any"))
        byte_copy (type, 2, DNS_T_ANY);
    else if (case_equals (s, "a"))
        byte_copy (type, 2, DNS_T_A);
    else if (case_equals (s, "ns"))
        byte_copy (type, 2, DNS_T_NS);
    else if (case_equals (s, "mx"))
        byte_copy (type, 2, DNS_T_MX);
    else if (case_equals (s, "ptr"))
        byte_copy (type, 2, DNS_T_PTR);
    else if (case_equals (s, "txt"))
        byte_copy (type, 2, DNS_T_TXT);
    else if (case_equals (s, "cname"))
        byte_copy (type, 2, DNS_T_CNAME);
    else if (case_equals (s, "soa"))
        byte_copy (type, 2, DNS_T_SOA);
    else if (case_equals (s, "hinfo"))
        byte_copy (type, 2, DNS_T_HINFO);
    else if (case_equals (s, "rp"))
        byte_copy (type,2,DNS_T_RP);
    else if (case_equals (s, "sig"))
        byte_copy (type, 2, DNS_T_SIG);
    else if (case_equals (s, "key"))
        byte_copy (type, 2, DNS_T_KEY);
    else if (case_equals (s, "aaaa"))
        byte_copy (type, 2, DNS_T_AAAA);
    else if (case_equals (s, "axfr"))
        byte_copy (type,2,DNS_T_AXFR);
    else
        return 0;

    return 1;
}
