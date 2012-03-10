\"
\" dnstrace.1: This is a manuscript of the manual page for `dnstrace'. This
\" file is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnstrace 1
dnstrace - a kind of traceroute(8) for DNS records

.SH SYNOPSYS
\fBdnstrace\fR [OPTIONS] <TYPE> <DOMAIN-NAME> <ROOT-IP> [<ROOT-IP> ...]

.SH DESCRIPTION
\fBdnstrace\fR is a useful debugging tool to search for all DNS servers that
can affect the resolution of records of given <TYPE> under the give
<DOMAIN-NAME> starting from the root name server <ROOT-IP>. \fBdnstrace\fR
uses the standard DNS resolution algorithm but follows all possible paths in
the algorithm. It prints all responses it receives from the DNS servers. It
also prints warnings about slow servers, dead servers, misdelegated servers
and misformatted packets.

  $ dnstrace A google.com 127.0.0.1 | dnstrcesort

One can use the \fBdnstracesort\fR in conjunction with the \fBdnstrace\fR. It
produces more human friendly sorted output.

.SH OPTIONS
.TP
.B \-h \-\-help
 print this help
.TP
.B \-v \-\-version
 print version information

.SH SEE
http://cr.yp.to/djbdns/debugging.html

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH Manual Author
Prasad J Pandit
