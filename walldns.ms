\"
\" walldns.8: This is a manuscript of the manual page for `walldns'. This file
\" is part of the 'New djbdns' project.
\"

\" No hyphenation
.hy
.nr HY 0

.TH walldns 8

.SH NAME
\fBwalldns\fR - a reverse DNS wall.

.SH SYNOPSIS
\fBwalldns\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBwalldns\fR is a reverse DNS wall. It accepts requests on UDP port 53. The
DNS queries are for the `in-addr.arpa' domain. Walldns rejects inverse
queries, non-internet class queries, truncated packets, packets that contain
anything other than a single question, queries for domains outside
in-addr.arpa and requests types other than A, PTR, and *.

.SH OPTIONS
.TP
.B \-d <value>
 print debug messages as per debug level: 1, 2, or 3
.TP
.B \-D
 run as a daemon
.TP
.B \-h \-\-help
 print this help
.TP
.B \-v \-\-version
 print version information

.SH FILES
 PREFIX/ndjbdns/walldns.conf

 /var/log/walldns.log

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
