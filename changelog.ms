\" Use nroff -ms <file-name> to format this file.
\"

.ll 6i
.pl 66
.po 1i

.nr LL 6i
.nr PL 66
.nr PO 1i

\" No hyphenation
.hy 0
.nr HY 0

.LP
Major changes
.br
=============

.IP "+ djbdns-1.05.3" 4

- Commands included tinydns, tinydns-data, tinydns-edit,
  tinydns-get, dnstrace and couple more.
.br
- The new commands now accept command-line options.
.br
- tinydns now reads from etc/djbdns/tinydns.conf and
  logs messages to /var/log/tinydns.log and requires no
  support from daemontools.
.br
- New manuals written for djbdns, tinydns, tinydns-*.
.br
- All the changes done so far are ported to FreeBSD.
  So from this release onwards, it will work on FreeBSD
  and hopefully on other Unixes as well.
.br
- Source files formatted for reading & hacking comfort.


.IP "+ djbdns-1.05.2" 4

- Commands included dnsip, dnsipq, dnsq & dnstracesort
.br
- dnsip, dnsipq & dnsq accept some command-line options
.br
- New manual pages written for dnsip & dnsq commands.
.br
- Four patches applied including the latest from Matthew
  Dempsky (see ChangeLog for more details).
.br
- COPYING changed to GPLv2 instead of GPLv3.
.br
- Source files formatted for reading & hacking comfort.


.IP "+ djbdns-1.05.1" 4

- This release is distributed under GNU GPL.
.br
- dnscache now supports few command line options.
.br
- dnscahe comes with a new manual page.
.br
- dnscache now reads configuration from dnscache.conf.
.br
- dnscache logs messages to /var/log/dnscache.log.
.br
- The build system makes use of GNU auto tools.
.br
- Unused or unnecessary files and commands dropped.
