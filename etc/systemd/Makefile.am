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

confdir = $(prefix)/lib/systemd/system/
conf_DATA = axfrdns@.service axfrdns.socket dnscache.service rbldns.service \
	tinydns.service walldns.service

$(conf_DATA): axfrdns.sysd axfrdns.sock dnscache.sysd rbldns.sysd \
	tinydns.sysd walldns.sysd
	sed -e 's:PREFIX:${prefix}:' axfrdns.sysd > axfrdns@.service
	sed -e ''                    axfrdns.sock > axfrdns.socket
	sed -e 's:PREFIX:${prefix}:' dnscache.sysd > dnscache.service
	sed -e 's:PREFIX:${prefix}:' rbldns.sysd > rbldns.service
	sed -e 's:PREFIX:${prefix}:' tinydns.sysd > tinydns.service
	sed -e 's:PREFIX:${prefix}:' walldns.sysd > walldns.service

CLEANFILES = $(conf_DATA)
EXTRA_DIST = axfrdns.sysd axfrdns.sock dnscache.sysd rbldns.sysd \
	tinydns.sysd walldns.sysd
