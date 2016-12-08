\"
\" dnstxt.1: This is a manuscript of the manual page for `dnstxt'. This file
\" is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnstxt 1
dnstxt - query DNS TXT record

.SH SYNOPSIS
.TP 5
\fBdnstxt\fR [\fBOPTIONS\fR] <domain-name> [<domain-name> ...]

.SH DESCRIPTION
.PP
\fBdnstxt\fR accepts a list of fully qualified domain names, queries and
displays TXT records for each of them. Each record is displayed on a
separate line.

A TXT record is used to store any human readable text. Lately it has been
known to store binary data such as Sender Policy Framework(SPF) details or
opportunistic encryption details etc.

.SH OPTIONS
.TP
.B \-h \-\-help
 print this help
.TP
.B \-v \-\-version
 print version information

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH Manual Author
Prasad J Pandit
