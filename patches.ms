\" Use nroff -ms <file-name> to format this file.
\"

.ll 6.5i
.pl 66
.po 1i

.nr LL 6.5i
.nr PL 66
.nr PO 1i

\" No hyphenation
.hy 0
.nr HY 0

\" Page header
.ds LH
.ds CH
.ds RH

\" Page footer
.ds LF
.ds CF
.ds RF

.LP
So far the following patches have been applied and the work is under progress
for others. Note that, the following patches were not created for the current
source tree, so I've manually done the changes to the same effect.

.IP response.c:
Patched with the latest 'response_len < 16384' patch from Matthew Dempsky.
.sp
Original author: Matthew Dempsky
.br
Url: http://marc.info/?l=djbdns&m=123613000920446&w=2

.IP dns_transmit.c:
Patched with the 'd->pos = 0' and 'char udpgbuf[4096]' patch from Matthew
Dempsky.
.sp
Original author: Matthew Dempsky
.br
Url: http://marc.info/?l=djbdns&m=119983010611174&w=3
.br
     http://marc.info/?l=djbdns&m=122368590802063&w=2

.IP dnscache.c:
Patched with the SIGPIPE patch from Mark Delany
.sp
Original author: Mark Delany
.br
Url: http://marc.info/?l=djbdns&m=104804013229536&w=2

.IP error.h:
Patched to #include <errno.h> on Linux Machines.
.sp
Original author: pjp
.sp
#if defined (linux) || defined (__linux)
.br
.in +4
    #include <errno.h>
.in -4
.br
#endif
