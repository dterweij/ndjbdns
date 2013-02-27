\"
\" tcprules.1: This is a manuscript of the manual page for `tcprules'. This
\" file is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH tcprules 1
tcprules - compile rules for tcpserver

.SH SYNOPSIS
.TP 5
\fBtcprules\fR [\fBOPTIONS\fR] <rules.cdb> <rules.tmp>

.SH DESCRIPTION
\fBtcprules\fR reads rules from its standard input and writes them into cdb
binary format suitable for quick access by tcpserver(1). \fBtcprules\fR can be
used while tcpserver(1) is running. It ensures that cdb is updated
automatically. It does it by first writing the rules to a temporary file and
then writing the temporary file to the cdb. If the temporary file already
exists, it is destroyed.

.SH RULE FORMAT
A rule is one line. A file containing rules may also contain comments
beginning with '#'. Each rule contains an address, a colon, and a list of
instructions, with no extra spaces. When tcpserver(1) receives a connection
from that address, it follows the instruction. tcpserver(1) uses the first
rule it matches.

tcprules treats 1.2.3.37-43:ins as an abbreviation for the rules
1.2.3.37:ins - 1.2.3.43:ins. Similarly 10.2-3 is an abbreviation for 10.2.:ins
and 10.3.:ins.

The instructions in a rule must begin with an allow or deny. deny tells
tcpserver(1) to drop the connection without processing any further.

.SH OPTIONS
.TP
.B \-h \-\-help
 print this help

.TP
.B \-v \-\-version
 print version information

.SH SEE
http://cr.yp.to/ucspi-tcp/tcprules.html

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH Manual Author
Prasad J Pandit
