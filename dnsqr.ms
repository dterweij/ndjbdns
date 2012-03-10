\"
\" dnsqr.1: This is a manuscript of the manual page for `dnsqr'. This file is
\" part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnsq 1
dnsqr - query DNS record

.SH SYNOPSYS
.TP 5
\fBdnsqr\fR [\fBOPTIONS\fR] <record-type> <domain-name>

.SH DESCRIPTION
.PP
\fBdnsqr\fR lets you query for specific type of records about a given
domain name. \fBdnsqr\fR supports the following options:

.SH OPTIONS
.TP
.B \-h \-\-help
 print this help
.TP
.B \-v \-\-version
 print version information

.SH RECORD TYPES
A record-type could be any of the following types

.TP
A
Returns an IPv4 host address for the given domain name.

.TP
ANY
Returns any records that are available for the given domain name.

.TP
NS
Returns an authoritative name server for the given domain name.

.TP
MX
Returns the Mail Exchange for the given domain name.

.TP
PTR
Returns a pointer to another part of the domain name space.

.TP
TXT
Returns a textual representation of the records for the given domain name.

.TP
CNAME
Returns a canonical name of the given domain name or for an alias.

.TP
SOA
Returns the Start of a Zone of Authority.

.TP
HINFO
Returns information such as CPU and OS used by the host.

.TP
RP
Returns a responsible person records for the given domain name.

.TP
SIG
Returns a security signature for the given domain name.

.TP
KEY
Returns a security key for the given domain name.

.TP
AAAA
Returns an IPv6 host address for the given domain name.

.TP
AXFR
Request for a transfer of an entire zone.


.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH Manual Author
Prasad J Pandit
