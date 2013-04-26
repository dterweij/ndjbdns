##
## Process this file with automake to produce 'Makefile.in'
##
## To create the configure script using this file follow these steps
## in order
## 1. write Makefile.am
## 2. autoscan
## 3. aclocal
## 4. autoheader
## 5. autoconf
## 6. automake -ac --foreign
##

confdir = $(sysconfdir)/ndjbdns/servers
conf_DATA = roots

$(conf_DATA): dnsroots.global
	cp dnsroots.global roots

CLEANFILES = $(conf_DATA)
EXTRA_DIST = dnsroots.global
