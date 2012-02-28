Name:		ndjbdns
Version:	1.05.4
Release:	4%{?dist}
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
integration with the `service' framework. This new release is free from
the clutches of `daemon-tools'. The original source is in public-domain
since late Dec 2007(see: http://cr.yp.to/distributors.html); Nevertheless,
this release is distributed under the GNU General Public Licence for good.
See ChangeLog for more details.


%prep
%setup -q %{name}


%build
export CFLAGS="$CFLAGS $RPM_OPT_FLAGS"
./configure --prefix=/usr --sysconfdir=/etc --libdir=%{_libdir}
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT INSTALL="install -p"

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/init.d
mv $RPM_BUILD_ROOT/%{_bindir}/tinydnsd $RPM_BUILD_ROOT/%{_sysconfdir}/init.d/
mv $RPM_BUILD_ROOT/%{_bindir}/dnscached $RPM_BUILD_ROOT/%{_sysconfdir}/init.d/

mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
mv dnscache.service $RPM_BUILD_ROOT/%{_unitdir}/
mv tinydns.service $RPM_BUILD_ROOT/%{_unitdir}/

%post
if [ $1 = 1 ]; then
    chkconfig --add dnscached
fi


%preun
if [ $1 = 0 ]; then
    chkconfig --del tinydnsd
    chkconfig --del dnscached
fi


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README COPYING ChangeLog

%{_bindir}/*
%{_sysconfdir}/init.d/tinydnsd
%{_sysconfdir}/init.d/dnscached

%{_unitdir}/dnscache.service
%{_unitdir}/tinydns.service

%config(noreplace) %{_sysconfdir}/djbdns/ip/127.0.0.1
%config(noreplace) %{_sysconfdir}/djbdns/tinydns.conf
%config(noreplace) %{_sysconfdir}/djbdns/axfrdns.conf
%config(noreplace) %{_sysconfdir}/djbdns/servers/roots
%config(noreplace) %{_sysconfdir}/djbdns/dnscache.conf

%{_mandir}/man1/*


%changelog
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
