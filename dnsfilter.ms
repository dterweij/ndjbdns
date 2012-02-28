\"
\" dnsfilter.1: This is a manuscript of the manual page for `dnsfilter'. This
\" file is part of the `djbdns' project version 1.05.2 or greater.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnsfilter 1
dnsfilter - convert IP address to host name

.SH SYNOPSYS
.TP 5
\fBdnsfilter\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBdnsfilter\fR does the opposite of dnsip. It inverse queries the DNS to
convert a given IP address to the corresponding host name. When a query
returns the host name, \fBdnsfilter\fR prints the result as

.in +4
<ip-address>=<host-name>
.in -4

and in case of any error it goes like

.in +4
<ip-address>:<error-message>
.in -4

.SH OPTIONS
.TP
.B \-c <number>
 do <number> queries in parallel
.TP
.B \-h \-\-help
 print this help
.TP
.B \-l <number>
 read ahead at most <number> lines
.TP
.B \-v \-\-version
 print version information

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
