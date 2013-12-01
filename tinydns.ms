\"
\" tinydns.8: This is a manuscript of the manual page for `tinydns'. This file
\" is part of the `New djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH tinydns 8

.SH NAME
\fBtinydns\fR - DNS server.

.SH SYNOPSIS
\fBtinydns\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBtinydns\fR is a DNS server that answers DNS queries from other hosts with
locally configured information. When invoked, \fBtinydns\fR reads from the
configuration file and listens on UDP port 53 for the incoming requests. When
a request is received, \fBtinydns\fR answers it by looking into `data.cdb'
file placed under the ROOT directory specified in the configuration file.

Until version 1.05.8, \fBtinydns\fR used to read from `data.cdb' for each
request it received and responded to. From version 1.05.9, \fBtinydns\fR reads
`data.cdb' only ones at the beginning and later when signaled for the same
via SIGUSR1.

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

.SH SIGNALS
SIGUSR1 - reload information from data.cdb file.

.SH FILES
 PREFIX/ndjbdns/tinydns.conf

 /var/log/tinydnsd.log

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
