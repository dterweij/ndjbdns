\"
\" dnscache.1: This is a manuscript of the manual page for `dnscache'. This
\" file is part of the `djbdns' project version 1.05.1 and later.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnscache 1
.SH NAME
\fBdnscache\fR - djbdns DNS cache daemon.

.SH SYNOPSYS
.TP 5
\fBdnscache\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBdnscache\fR is a program used to map a given domain name to it's
IP address and vice versa. When invoked, \fBdnscache\fR reads from the
configuration file and listens on TCP/UDP port 53 for the incoming requests.
\fBdnscache\fR is a part of the \fBdjbdns\fR project, originally written by
the eminent author of qmail, Dr. D J Bernstein. \fBdjbdns\fR is a collection
of programs, together which form a Domain Name System(DNS for short) as
instructed in RFC-1034, 1035.

Typically \fBdnscache\fR accepts incoming requests only from the
localhost(127.0.0.1). To accept requests from external machine or subnet,
touch(1) a file with the name same as an IP address of the machine or subnet,
under the `ip/' directory listed below. So \fBdnscache\fR would accept a
packet from IP address 1.2.3.4, if only it sees a file named 1.2.3.4 OR 1.2.3
OR 1.2 OR 1. under the `ip/' directory.

To resolve a domain name, \fBdnscache\fR contacts the name servers
listed by the files under `servers/' directory. File `@' lists the root name
servers. \fBdnscache\fR would contact servers listed in the
`servers/mydomain.com' file, to resolve domain names that end with mydomain.com,
like say: mail.mydomain.com or irc.mydomain.com etc.

Note: these files list IP addresses of name servers one on each line.

.SH OPTIONS
.TP
.B \-d <value>
 print debug messages as per the debug level 1, 2 or 3.
.TP
.B \-D
 run as a daemon.
.TP
.B \-h \-\-help
 print this help.
.TP
.B \-v \-\-version
 print version information.

.SH FILES
 PREFIX/djbdns/ip/
 PREFIX/djbdns/servers/
 PREFIX/djbdns/dnscache.conf

 /var/log/dnscached.log

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
