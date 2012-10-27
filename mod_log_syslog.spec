%define name	%{mod_name}
%define version %{mod_version}
%define release 1
%define github_user tkyk

# Module-Specific definitions
%define mod_version	0.1.0
%define mod_basename	log_syslog
%define mod_name	mod_%{mod_basename}
%define mod_conf	%{mod_basename}.conf
%define mod_so		%{mod_name}.so
%define sourcename	%{name}-%{mod_version}
%define apxs_path	/usr/sbin

Summary:	Apache module to send access logs to syslog.
Name:		%{name}
Version:	%{version}
Release:	%{release}
License:	MIT License
Group:		System Environment/Daemons
URL:		http://github.com/%{github_user}/mod_log_syslog/tree/master
Source0:	http://cloud.github.com/downloads/%{github_user}/mod_log_syslog/%{sourcename}.tar.gz

BuildRoot:	%{_tmppath}/%{name}-buildroot
BuildRequires:	sed
BuildPrereq:	httpd-devel >= 2.2, apr-devel, glibc-headers
Provides:	mod_log_syslog
Requires:	httpd >= 2.2

%description
mod_log_syslog is an Apache module to send access logs to syslog.

%prep
%setup -q

%build
%{__make} PATH=%{apxs_path}:$PATH

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
%{__install} -d %{buildroot}%{_libdir}/httpd/modules/
%{__install} -d %{buildroot}%{_sysconfdir}/httpd/conf.d/
%{__install} -m0755 .libs/%{mod_so} %{buildroot}%{_libdir}/httpd/modules/
%{__install} -m0644 %{mod_conf} %{buildroot}%{_sysconfdir}/httpd/conf.d/

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%post

%postun

%files
%defattr(-,root,root)
%{_libdir}/httpd/modules/%{mod_so}
%config(noreplace) %{_sysconfdir}/httpd/conf.d/%{mod_conf}

%changelog
* Fri Oct 26 2012 Takayuki Miwa <i@tkyk.name> - 0.1.0-1
- Initial package.

