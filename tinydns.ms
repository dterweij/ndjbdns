\"
\" tinydns.1: This is a manuscript of the manual page for `tinydns'. This file
\" is part of the `djbdns' project version 1.05.3 and later.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH tinydns 1

.SH NAME
\fBtinydns\fR - DNS server.

.SH SYNOPSYS
\fBtinydns\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBtinydns\fR is a DNS server that answers DNS queries from other hosts with
locally configured information. When invoked, \fBtinydns\fR reads from the
configuration file and listens on UDP port 53 for the incoming requests. When
the request is received, \fBtinydns\fR answers it by looking into `data.cdb'
file placed under the ROOT directory specified in the configuration file.

.SH OPTIONS
.TP
.B \-d <value>
 print debug messages as per the debug level 1, 2 or 3.
.TP
.B -D
 run as a daemon.
.TP
.B \-h \-\-help
 print this help.
.TP
.B \-v \-\-version
 print version information.

.SH FILES
 PREFIX/djbdns/tinydns.conf

 /var/log/tinydnsd.log

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
