\"
\" rbldns-data.1: This is a manuscript of the manual page for `rbldns-data'.
\" This file is part of the `New djbdns' project.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH rbldns-data 1

.SH NAME
\fBrbldns-data\fR

.SH SYNOPSIS
\fBrbldns-data\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
\fBrbldns-data\fR is used to generate the binary file `data.cdb', used by
\fBrbldns\fR server to answer the user requests. \fBrbldns-data\fR reads the
Real time Block List(RBL) or Dialup Users List(DUL) information from a file
called `data' in the current directory and writes a binary file `data.cdb' in
the same directory. One can update `data.cdb' while \fBrbldns\fR is running.
\fBrbldns-data\fR leaves the old .cdb file intact in case if something goes
wrong while updating data.cdb.

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
