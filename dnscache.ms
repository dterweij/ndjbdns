\"
\" dnscache.8: This is a manuscript of the manual page for `dnscache'. This
\" file is part of the `djbdns' project version 1.05.1 and later.
\"

\" No hyphenation
.hy 0
.nr HY 0

.TH dnscache 8
.SH NAME
\fBdnscache\fR - djbdns DNS cache daemon.

.SH SYNOPSIS
.TP 5
\fBdnscache\fR [\fBOPTIONS\fR]

.SH DESCRIPTION
.PP
\fBdnscache\fR is used to map a domain name to its IP address and vice versa.
Upon invocation, \fBdnscache\fR reads from its configuration file and listens
on TCP/UDP port 53 for incoming requests. Typically \fBdnscache\fR accepts
incoming requests only from localhost(127.0.0.1). To accept requests from
external machine or subnet, create a file, named after the IP address of a
machine or subnet from which to accept requests, under the `ip/' directory.
Ie. \fBdnscache\fR would accept requests from IP address 1.2.3.4, if there is
a file named 1.2.3.4 OR 1.2.3 OR 1.2 OR 1. under the `ip/' directory.

To resolve a domain name, \fBdnscache\fR contacts the name servers listed in
files under the `servers/' directory. File `roots' lists the root name servers.
\fBdnscache\fR would contact servers listed in the `servers/mydomain.com' file,
to resolve domain names that end with mydomain.com, like say: mail.mydomain.com
or irc.mydomain.com etc.
Note: these files list IP addresses of name servers one on each line.

From version \fB1.05.9\fR, \fBdnscache\fR introduced support for the
DNS(or Domain) Block List. DNS Block List is a list of domain names which are
to be blocked by the resolver. Client requests querying for such domain names
are dropped by the resolver. This would add an additional layer of security
for DNS clients and also help to reduce malicious traffic.

DNS block list is a 'cdb' database created using tinydns-data(1) tool. List the
malicious domain names into a 'data' file as generic domain records,
one on each line, as:

    :bad.domain.com:284::::

Number '284' is not used, it can be any number between 256...65535.
tinydns-data(1) would create a 'data.cdb' database from this 'data' file.
Rename \fBdata.cdb\fR to \fBdnsbl.cdb\fR, because that is the file read by
\fBdnscache\fR server.

    $ mv data.cdb dnsbl.cdb

\fBdnscache\fR would read 'dnsbl.cdb' from its working($ROOT) directory
defined in the 'dnscache.conf' file.

.SH OPTIONS
.TP
.B \-d <value>
 print debug messages as per the debug level 1, 2 or 3.
.TP
.B \-D
 run as a daemon.
.TP
.B \-h \-\-help
 print this help.
.TP
.B \-v \-\-version
 print version information.

.SH FILES
 PREFIX/ndjbdns/ip/
 PREFIX/ndjbdns/servers/
 PREFIX/ndjbdns/dnscache.conf

 /var/log/dnscached.log

.SH BUGS
Report bugs to <pj.pandit@yahoo.co.in>

.SH AUTHOR
Prasad J Pandit
