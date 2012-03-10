\"
\" dnsipq.1: This is a manuscript of the manual page for `dnsipq'. This file
\" is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnsipq 1
dnsipq - DNS lookup tool

.SH SYNOPSYS
.TP 5
\fBdnsipq\fR [\fBOPTIONS\fR] <domain-name> [<domain-name> ...]

.SH DESCRIPTION
.PP
\fBdnsipq\fR accepts a list of fully qualified domain names, resolves each of
them and prints a record of the form:

    <domain-name> <ip-address>

for each domain name.

.SH OPTIONS
.TP
.B \-h \-\-help
 print this help
.TP
.B \-v \-\-version
 print version information

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
