\"
\" tinydns-data.1: This is a manuscript of the manual page for `tinydns-data'.
\" This file is part of the `djbdns' project version 1.05.3 and later.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH tinydns-data 1

.SH NAME
\fBtinydns-data\fR

.SH SYNOPSYS
\fBtinydns-data\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
\fBtinydns-data\fR is used to generate the binary file `data.cdb', used by
\fBtinydns\fR server to answer the user requests. \fBtinydns-data\fR reads
the DNS information from a file `data' in the current directory and writes
a binary file data.cdb in the same directory. One can update `data.cdb' while
\fBtinydns\fR is running. \fBtinydns-data\fR leaves the old .cdb file intact
in case if something goes wrong while updating data.cdb.

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
