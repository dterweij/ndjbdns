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
conf_SCRIPTS = dnscache rbldns tinydns walldns

$(conf_SCRIPTS): dnscache.sh rbldns.sh tinydns.sh walldns.sh
	sed -e 's:PREFIX:${prefix}:' dnscache.sh > dnscache
	sed -e 's:PREFIX:${prefix}:' rbldns.sh > rbldns
	sed -e 's:PREFIX:${prefix}:' tinydns.sh > tinydns
	sed -e 's:PREFIX:${prefix}:' walldns.sh > walldns

xinetdir = $(sysconfdir)/xinetd.d/
xinet_SCRIPTS = axfrdns

$(xinet_SCRIPTS): axfrdns.xinet
	sed -e '' axfrdns.xinet > axfrdns

CLEANFILES = $(conf_SCRIPTS) $(xinet_SCRIPTS)
EXTRA_DIST = axfrdns.xinet dnscache.sh rbldns.sh tinydns.sh walldns.sh
