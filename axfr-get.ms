\"
\" axfrget.1: This is a manuscript of the manual page for `axfrget'. This file
\" is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH axfrget 1
axfr-get - a DNS zone transfer client.

.SH SYNOPSYS
.TP 5
\fBaxfr-get\fR [OPTIONS] <DOMAIN-NAME> <OUTFILE> <OUTFILE.TMP>

.SH DESCRIPTION
\fBaxfr-get\fR is a DNS zone transfer client. It sends a zone transfer request
in DNS-over-TCP format to descriptor 7, reads the result from descriptor 6 and
saves the result in a file.

\fBaxfr-get\fR performs the zone transfer for the given domain, and writes the
result to file - OUTFILE.TMP in a format that can be used as input to
tinydns-data(1). If the zone transfer completes successfully, axfr-get
renames OUTFILE.TMP to OUTFILE.

.SH SEE
http://cr.yp.to/djbdns/axfr-get.html

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH Manual Author
Prasad J Pandit
