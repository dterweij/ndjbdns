\"
\" randomip.1: This is a manuscript of the manual page for `randomip'. This
\" file is part of the `new djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH randomip 1
randomip - generate random IP addresses

.SH SYNOPSIS
.TP 5
\fBrandomip\fR [OPTIONS] [NUM] [BYTE1] [BYTE2] [BYTE3]

.SH DESCRIPTION
\fBrandomip\fR is a simple tool to generate specified number of random IP
addresses. By default it generates 10,000 of them. One can specify how many IP
addresses to generate followed by the first, second and third byte of the IP
address.

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
