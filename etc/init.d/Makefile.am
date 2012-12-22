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
conf_SCRIPTS = axfrdnsd dnscached tinydnsd

$(conf_SCRIPTS): axfrdns.sh dnscache.sh tinydns.sh
	sed -e 's:PREFIX:${prefix}:' axfrdns.sh > axfrdnsd
	sed -e 's:PREFIX:${prefix}:' dnscache.sh > dnscached
	sed -e 's:PREFIX:${prefix}:' tinydns.sh > tinydnsd

CLEANFILES = $(conf_SCRIPTS)
EXTRA_DIST = axfrdns.sh dnscache.sh tinydns.sh
