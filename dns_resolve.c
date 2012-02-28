#include <string.h>

#include "dns.h"
#include "taia.h"
#include "byte.h"
#include "iopause.h"

struct dns_transmit dns_resolve_tx;

int
dns_resolve (const char *q, const char qtype[2])
{
    int r = 0;
    char servers[64];
    iopause_fd x[1];

    struct taia stamp;
    struct taia deadline;

    if (dns_resolvconfip (servers) == -1)
        return -1;

    memset (&dns_resolve_tx, 0, sizeof (dns_resolve_tx));
    r = dns_transmit_start (&dns_resolve_tx, servers, 1, q, qtype, "\0\0\0\0");
    if (r == -1)
        return -1;

    for (;;)
    {
        taia_now (&stamp);
        taia_uint (&deadline, 120);
        taia_add (&deadline, &deadline, &stamp);

        dns_transmit_io (&dns_resolve_tx, x, &deadline);
        iopause (x, 1, &deadline, &stamp);

        r = dns_transmit_get (&dns_resolve_tx, x, &stamp);
        if (r == -1)
            return -1;
        if (r == 1)
            return 0;
    }
}
