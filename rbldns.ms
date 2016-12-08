\"
\" rbldns.8: This is a manuscript of the manual page for `rbldns'. This file
\" is part of the 'New djbdns' project.
\"

\" No hyphenation
.hy
.nr HY 0

.TH rbldns 8

.SH NAME
\fBrbldns\fR - Real time Block List DNS server.

.SH SYNOPSIS
\fBrbldns\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBrbldns\fR is a Real time Block List DNS server. It accepts iterative DNS
queries from clients seeking information about IP addresses. It provides
responses showing whether the addresses are listed on the locally configured
Real time Block List(RBL) or Dialup Users List(DUL). When invoked,
\fBrbldns\fR reads from the configuration file and listens on UDP port 53 for
the incoming requests. When the request is received, \fBrbldns\fR answers it
by looking in the data.cdb file placed under the ROOT directory specified in
the configuration file.

.SH OPTIONS
.TP
.B \-d <value>
 print debug messages as per the debug level, 1, 2 or 3.
.TP
.B -D
 run as a daemon
.TP
.B \-h \-\-help
 print this help.
.TP
.B \-v \-\-version
 print version information.

.SH FILES
 PREFIX/ndjbdns/rbldns.conf

 /var/log/rbldns.log

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
