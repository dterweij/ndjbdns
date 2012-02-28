\"
\" tinydns-edit.1: This is a manuscript of the manual page for `tinydns-edit'.
\" This file is part of the `djbdns' project version 1.05.3 and later.
\"

\" Np hyphenaion
.hy 0
.nr HY 0

.TH tinydns-edit 1

.SH NAME
\fBtinydns-edit\fR

.SH SYNOPSYS
\fBtinydns-edit\fR [\fBOPTIONS\fR] DATA DATA.TMP add TYPE NAME ADDRESS

.SH DESCRIPTION
\fBtinydns-edit\fR write the DNS records to the `data' file, which in turn is
used by \fBtinydns-data\fR to generate the binary .cdb file used by
\fBtinydns\fR or \fBaxfrdns\fR server. The command line parameters required by
\fBtinydns-edit\fR are

.IP DATA
is a path of the `data' file to be written.

.IP DATA.TMP
is a path of the temporary file to be used by tinydns-edit for creating the
DATA file.

.IP add
is a mandatory command.

.IP TYPE
is the DNS record type, and could be any of the following
.sp
ns: name server record, specifies that the NAME is published by a DNS
server at ADDRESS.
.sp
childns: specifies that requests for the domain NAME should be referred to a
child DNS server at ADDRESS.
.sp
mx: this record says, mail to names in the domain NAME should be sent to an
SMTP server at ADDRESS.
.sp
host: this record says that the domain NAME maps to an address ADDRESS and
vice versa.
.sp
alias: this record says that the domain NAME maps to the address ADDRESS
but the reverse is not true.

.IP NAME
is the domain name to be appended to the DATA file.

.IP ADDRESS
is the respective address for the domain NAME.

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
