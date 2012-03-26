Name:		ndjbdns
Version:	1.05.4
Release:	9%{?dist}
Summary:	New djbdns: usable djbdns

Group:		Applications/System
License:	GPLv2+
URL:		http://pjp.dgplug.org/djbdns/
Source0:	http://pjp.dgplug.org/djbdns/%{name}-%{version}.tar.gz
BuildRequires:	systemd-units


%description
New djbdns: is a usable fork of djbdns. `djbdns' is a Domain Name System
originally written by the eminent author of Qmail, Dr D. J. Bernstein.
This *new* version of djbdns is a complete makeover to the original
source(djbdns-1.05) and is meant to make life a lot more pleasant. The
notable changes so far are in the set-up & configuration steps and
integration with the systemd(1) framework. This new release is free from
the clutches of `daemon-tools'. The original source is in public-domain
since late Dec 2007(see: http://cr.yp.to/distributors.html);


%prep
%setup -q %{name}


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT INSTALL="install -p"

mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
mv axfrdns.service $RPM_BUILD_ROOT/%{_unitdir}/
mv dnscache.service $RPM_BUILD_ROOT/%{_unitdir}/
mv tinydns.service $RPM_BUILD_ROOT/%{_unitdir}/

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/
mv ndjbdns.logrotate $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/ndjbdns


%files
%doc README COPYING ChangeLog

%{_bindir}/axfrdns
%{_bindir}/axfr-get
%{_bindir}/dnscache
%{_bindir}/dnsfilter
%{_bindir}/dnsip
%{_bindir}/dnsipq
%{_bindir}/dnsname
%{_bindir}/dnsq
%{_bindir}/dnsqr
%{_bindir}/dnstrace
%{_bindir}/dnstracesort
%{_bindir}/dnstxt
%{_bindir}/randomip
%{_bindir}/tcprules
%{_bindir}/tinydns
%{_bindir}/tinydns-data
%{_bindir}/tinydns-edit
%{_bindir}/tinydns-get

%{_unitdir}/axfrdns.service
%{_unitdir}/dnscache.service
%{_unitdir}/tinydns.service

%config(noreplace) %{_sysconfdir}/%{name}/ip/127.0.0.1
%config(noreplace) %{_sysconfdir}/%{name}/tinydns.conf
%config(noreplace) %{_sysconfdir}/%{name}/axfrdns.conf
%config(noreplace) %{_sysconfdir}/%{name}/servers/roots
%config(noreplace) %{_sysconfdir}/%{name}/dnscache.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/ndjbdns

%{_mandir}/man1/axfrdns.1.gz
%{_mandir}/man1/axfr-get.1.gz
%{_mandir}/man1/djbdns.1.gz
%{_mandir}/man1/dnscache.1.gz
%{_mandir}/man1/dnsfilter.1.gz
%{_mandir}/man1/dnsip.1.gz
%{_mandir}/man1/dnsipq.1.gz
%{_mandir}/man1/dnsname.1.gz
%{_mandir}/man1/dnsq.1.gz
%{_mandir}/man1/dnsqr.1.gz
%{_mandir}/man1/dnstrace.1.gz
%{_mandir}/man1/dnstxt.1.gz
%{_mandir}/man1/randomip.1.gz
%{_mandir}/man1/tcprules.1.gz
%{_mandir}/man1/tinydns.1.gz
%{_mandir}/man1/tinydns-data.1.gz
%{_mandir}/man1/tinydns-edit.1.gz
%{_mandir}/man1/tinydns-get.1.gz


%changelog
* Tue Mar 13 2012 pjp <pj.pandit@yahoo.co.in> - 1.05.4-9
- added logrotate configuration file /etc/logrotate.d/ndjbdns and a
  systemd service unit file: axfrdns.service.

* Mon Mar 12 2012 pjp <pj.pandit@yahoo.co.in> - 1.05.4-8
- listed individual files under _bindir and _mandir. Removed wild card: *.

* Sun Mar 11 2012 pjp <pj.pandit@yahoo.co.in> - 1.05.4-7
- added user manual for commands. Removed couple of commands.

* Fri Mar  2 2012 pjp <pj.pandit@yahoo.co.in> - 1.05.4-6
- renamed /etc/djbdns to /etc/ndjbdns; removed the clean section above.

* Tue Feb 28 2012 pjp <pj.pandit@yahoo.co.in> - 1.05.4-5
- removed SysV init scripts, replaced ./configure with the configure macro.

* Fri Feb 24 2012 pjp <pj.pandit@yahoo.co.in> - 1.05.4-4
- added systemd service unit files. Patch from Jose - jmalv04.

* Tue Jul 26 2011 pjp <pj.pandit@yahoo.co.in> - 1.05.4-3
- name changed to ndjbdns: New djbdns.

* Thu Apr  7 2011 pjp <pj.pandit@yahoo.co.in> - 1.05.4-2
- renamed default root server list from servers/@ to servers/roots.

* Thu Jan  6 2011 pjp <pj.pandit@yahoo.co.in> - 1.05.4-1
- init service script djbdns renamed to dnscached. and added a new service
  tinydnsd for DNS server.

* Wed Aug 19 2009 pjp <pj.pandit@yahoo.co.in> - 1.05.3-2
- Changes made to the build, install & files sections above, as indicated in
  the package review: https://bugzilla.redhat.com/show_bug.cgi?id=480724

* Sun Aug 16 2009 pjp <pj.pandit@yahoo.co.in> - 1.05.3-1
- A new release djbdns-1.05.3 of djbdns, includes tinydns and few more tools.

* Tue Mar 17 2009 pjp <pj.pandit@yahoo.co.in> - 1.05.2-1
- It's release 1 of new version 1.05.2 of djbdns.

* Fri Mar  6 2009 pjp <pj.pandit@yahoo.co.in> - 1.05.1-2
- changed README and the spec file to include reference to DJBs public-domain
  announcement at: http://cr.yp.to/distributors.html

* Thu Mar  5 2009 pjp <pj.pandit@yahoo.co.in> - 1.05.1-1
- Initial RPM release of djbdns-1.05.1
