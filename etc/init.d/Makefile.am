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

confdir = $(sysconfdir)/rc.d/init.d/
conf_SCRIPTS = axfrdns dnscache rbldns tinydns

$(conf_SCRIPTS): axfrdns.sh dnscache.sh rbldns.sh tinydns.sh
	sed -e 's:PREFIX:${prefix}:' axfrdns.sh > axfrdns
	sed -e 's:PREFIX:${prefix}:' dnscache.sh > dnscache
	sed -e 's:PREFIX:${prefix}:' rbldns.sh > rbldns
	sed -e 's:PREFIX:${prefix}:' tinydns.sh > tinydns

CLEANFILES = $(conf_SCRIPTS)
EXTRA_DIST = axfrdns.sh dnscache.sh rbldns.sh tinydns.sh
