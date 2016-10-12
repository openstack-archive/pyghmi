Summary: Python General Hardware Management Initiative (IPMI and others)
Name: python-pyghmi
Version: %{?version:%{version}}%{!?version:%(python setup.py --version)}
Release: %{?release:%{release}}%{!?release:1}
Source0: pyghmi-%{version}.tar.gz
License: Apache License, Version 2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Jarrod Johnson <jjohnson2@lenovo.com>
Url: https://git.openstack.org/cgit/openstack/pyghmi


%description
This is a pure python implementation of IPMI protocol.

pyghmicons and pyghmiutil are example scripts to show how one may incorporate
this library into python code



%prep
%setup -n pyghmi-%{version}

%build
python setup.py build

%install
python setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES --prefix=/usr

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)

