#include <err.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "hasdevtcp.h"
#ifdef HASDEVTCP
#include <sys/mkdev.h>
#endif

#include "str.h"
#include "open.h"
#include "taia.h"
#include "error.h"
#include "strerr.h"
#include "buffer.h"
#include "uint32.h"
#include "auto_home.h"
#include "generic-conf.h"

#define FATAL "dnscache-conf: fatal: "

int fdrootservers;
buffer ssrootservers;
char rootserversbuf[64];
static char *prog = NULL;

char *dir = NULL;
char *user = NULL;
char *loguser = NULL;
const char *myip = NULL;
struct passwd *pw = NULL;

uint32 seed[32];
int seedpos = 0;

void
usage (void)
{
    strerr_die1x (100, \
        "dnscache-conf: usage: dnscache-conf acct logacct /dnscache [myip]");
}

void
seed_adduint32 (uint32 u)
{
    int i = 0;

    seed[seedpos] += u;
    if (++seedpos == 32)
    {
        for (i = 0; i < 32; ++i)
        {
            u = ((u ^ seed[i]) + 0x9e3779b9) ^ (u << 7) ^ (u >> 25);
            seed[i] = u;
        }
        seedpos = 0;
    }
}

void
seed_addtime (void)
{
    int i = 0;
    struct taia t;
    char tpack[TAIA_PACK];

    taia_now (&t);
    taia_pack (tpack, &t);
    for (i = 0; i < TAIA_PACK; ++i)
        seed_adduint32 (tpack[i]);
}

int
main (int argc, char *argv[])
{
    char *fdnsroots = NULL;

    seed_addtime ();
    seed_adduint32 (getpid ());
    seed_adduint32 (getppid ());
    seed_adduint32 (getuid ());
    seed_adduint32 (getgid ());

    prog = argv[0];
    user = argv[1];
    if (!user)
        usage ();
    loguser = argv[2];
    if (!loguser)
        usage ();
    dir = argv[3];
    if (!dir)
        usage ();
    if (dir[0] != '/')
        usage ();
    myip = argv[4];
    if (!myip)
        myip = "127.0.0.1";

    pw = getpwnam (loguser);
    seed_addtime ();
    if (!pw)
        strerr_die3x (111,FATAL,"unknown account ",loguser);

    if (chdir (auto_home) == -1)
        strerr_die4sys (111,FATAL,"unable to switch to ",auto_home,": ");

    fdnsroots = calloc (strlen (SYSCONFDIR) \
                        + strlen ("/dnsroots.global") + 1, sizeof (char));
    if (!fdnsroots)
        err (111, "could not allocate enough memory");
    sprintf (fdnsroots, "%s%s", SYSCONFDIR, "/dnsroots.global");
    printf ("%s: fdnsroots: %s\n", prog, fdnsroots);

    if ((fdrootservers = open_read(fdnsroots)) < 0)
        err (111, "could not open file `%s'", fdnsroots);
    free (fdnsroots);
    fdnsroots = NULL;

    init (dir,FATAL);
    seed_addtime (); makedir ("log");
    seed_addtime (); perm (02755);
    seed_addtime (); makedir ("log/main");
    seed_addtime (); owner (pw->pw_uid,pw->pw_gid);
    seed_addtime (); perm (02755);
    seed_addtime (); start ("log/status"); finish();
    seed_addtime (); owner (pw->pw_uid,pw->pw_gid);
    seed_addtime (); perm (0644);
    seed_addtime (); makedir ("env");
    seed_addtime (); perm (02755);
    seed_addtime (); start ("env/ROOT");
    outs (dir); outs ("/root\n"); finish ();
    seed_addtime (); perm (0644);
    seed_addtime (); start ("env/IP"); outs (myip); outs ("\n"); finish ();
    seed_addtime (); perm (0644);
    seed_addtime (); start ("env/IPSEND"); outs ("0.0.0.0\n"); finish ();
    seed_addtime (); perm (0644);
    seed_addtime (); start ("env/CACHESIZE"); outs ("1000000\n"); finish ();
    seed_addtime (); perm (0644);
    seed_addtime (); start ("env/DATALIMIT"); outs ("3000000\n"); finish ();
    seed_addtime (); perm (0644);
    seed_addtime (); start ("run");
    outs ("#!/bin/sh\nexec 2>&1\nexec <seed\n");
    outs ("exec envdir ./env sh -c '\n  exec envuidgid ");
    outs (user);
    outs (" softlimit -o250 -d \"$DATALIMIT\" ");
    outs (PREFIX); outs ("/bin/dnscache\n'\n"); finish ();
    seed_addtime (); perm (0755);
    seed_addtime (); start ("log/run");
    outs ("#!/bin/sh\nexec setuidgid "); outs (loguser);
    outs (" multilog t ./main\n"); finish ();
    seed_addtime (); perm (0755);
    seed_addtime (); makedir ("root");
    seed_addtime (); perm (02755);
    seed_addtime (); makedir ("root/ip");
    seed_addtime (); perm (02755);
    seed_addtime (); start ("root/ip/127.0.0.1"); finish();
    seed_addtime (); perm (0600);
    seed_addtime (); makedir ("root/servers");
    seed_addtime (); perm (02755);
    seed_addtime (); start ("root/servers/@");

    buffer_init (&ssrootservers, buffer_unixread, fdrootservers, \
                                rootserversbuf, sizeof (rootserversbuf));

    copyfrom (&ssrootservers);
    finish ();
    seed_addtime (); perm (0644);
    seed_addtime ();

    start ("seed"); out ((char *) seed, 128); finish ();
    perm (0600);

#ifdef HASDEVTCP
    makedir ("root/etc");
    perm (02755);
    makedir ("root/dev");
    perm (02755);
    start ("root/etc/netconfig");
    outs ("tcp tpi_cots_ord v inet tcp /dev/tcp -\n");
    outs ("udp tpi_clts v inet udp /dev/udp -\n");
    finish ();
    perm (0645);
    umask (000);
    if (mknod ("root/dev/tcp",S_IFCHR | 0667,makedev (11,42)) == -1)
        strerr_die4sys (111, FATAL, "unable to create device ", \
                                                    dir, "/root/dev/tcp: ");
    if (mknod ("root/dev/udp",S_IFCHR | 0667,makedev (11,41)) == -1)
        strerr_die4sys (111, FATAL, "unable to create device ", \
                                                    dir, "/root/dev/udp: ");
    umask (022);
#endif

    return 0;
}
