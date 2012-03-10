\"
\" axfrdns.1: This is a manuscript of the manual page for `axfrdns'. This file
\" is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH axfrdns 1
axfrdns - a DNS zone transfer server.

.SH SYNOPSYS
.TP 5
\fBaxfrdns\fR [OPTIONS]

.SH DESCRIPTION
.PP
\fBaxfrdns\fR is a zone transfer server.  It reads a zone transfer request in
DNS-over-TCP format from its standard input and responds with a locally
configured information. \fBaxfrdns\fR looks up zone-transfer results in
data.cdb, a binary file created by tinydns-data(1). It also responds to normal
client queries such as SOA queries, which usually precede zone transfer
requests.

\fBaxfrdns\fR allows zone transfer for any zone listed in the $AXFR variable.
AXFR is a slash separated list of domain names. If AXFR is not set,
\fBaxfrdns\fR allows zone transfer for all zone available in data.cdb.

.SH OPTIONS
.TP
.B \-d <value>
 print debug messages
.TP
.B \-D
 run as daemon
.TP
.B \-h \-\-help
 print this help
.TP
.B \-v \-\-version
 print version information

.SH FILES
/etc/ndjbdns/axfrdns.conf

.SH SEE
http://cr.yp.to/djbdns/axfrdns.html

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH Manual Author
Prasad J Pandit
