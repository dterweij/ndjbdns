\"
\" tinydns-get.1: This is a manuscript of the manual page for `tinydns-get'.
\" This file is part of the `djbdns' project version 1.05.3 and later.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH tinydns-get 1

.SH NAME
\fBtinydns-get\fR - get the tinydns server records

.SH SYNOPSYS
\fBtinydns-get\fR [\fBOPTIONS\fR] TYPE NAME [IP]

.SH DESCRIPTION
\fBtinydns-get\fR is used to query the \fBtinydns\fR server records from the
data.cdb file in the current directory. If an IP is provided, it simulates the
results of a query from the given IP address. This matters if data.cdb is
different at different client locations.

.SH OPTIONS
.TP
.B \-h \-\-help
 print this help.
.TP
.B \-v \-\-version
 print version information.

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
