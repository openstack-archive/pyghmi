%global with_python3 1
%global sname pyghmi
%global common_summary Python General Hardware Management Initiative (IPMI and others)

%global common_desc This is a pure Python implementation of IPMI protocol. \
\
The included pyghmicons and pyghmiutil scripts demonstrate how one may \
incorporate the pyghmi library into a Python application.

%global common_desc_tests Tests for the pyghmi library

Summary: %{common_summary}
Name: python-%{sname}
Version: %{?version:%{version}}%{!?version:%(python setup.py --version)}
Release: %{?release:%{release}}%{!?release:1}
Source0: %{sname}-%{version}.tar.gz
License: Apache License, Version 2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Jarrod Johnson <jjohnson2@lenovo.com>
Url: https://git.openstack.org/cgit/openstack/pyghmi

%description
%{common_desc}

%package -n python2-%{sname}
Summary: %{common_summary}
%{?python_provide:%python_provide python2-%{sname}}

Requires: python2-cryptography

%description -n python2-%{sname}
%{common_desc}

%package -n python2-%{sname}-tests
Summary: %{common_desc_tests}
Requires: python2-%{sname} = %{version}-%{release}

%description -n python2-%{sname}-tests
%{common_desc_tests}

%if 0%{?with_python3}

%package -n python3-%{sname}
Summary: %{common_summary}
%{?python_provide:%python_provide python3-%{sname}}

Requires: python3-cryptography

%description -n python3-%{sname}
%{common_desc}

%package -n python3-%{sname}-tests
Summary: %{common_desc_tests}
Requires: python3-%{sname} = %{version}-%{release}

%description -n python3-%{sname}-tests
%{common_desc_tests}

%endif # with_python3

%package -n python-%{sname}-doc
Summary: The pyghmi library documentation

BuildRequires: python2-sphinx

%description -n python-%{sname}-doc
Documentation for the pyghmi library

%prep
%setup -n %{sname}-%{version}

%build
%py2_build
%if 0%{?with_python3}
%py3_build
%endif # with_python3

# generate html docs
%{__python2} setup.py build_sphinx -b html
# remove the sphinx-build leftovers
rm -rf doc/build/html/.{doctrees,buildinfo}

%install
# Setup directories
install -d -m 755 %{buildroot}%{_datadir}/%{sname}
install -d -m 755 %{buildroot}%{_sharedstatedir}/%{sname}
install -d -m 755 %{buildroot}%{_localstatedir}/log/%{sname}

%if 0%{?with_python3}
%py3_install

%files -n python3-%{sname}
%license LICENSE
%{python3_sitelib}/%{sname}
%{python3_sitelib}/%{sname}-*.egg-info
%exclude %{python3_sitelib}/%{sname}/tests

%files -n python3-%{sname}-tests
%license LICENSE
%{python3_sitelib}/%{sname}/tests

%endif # with_python3

%py2_install

%files -n python2-%{sname}
%license LICENSE
%{python2_sitelib}/%{sname}
%{python2_sitelib}/%{sname}-*.egg-info
%exclude %{python2_sitelib}/%{sname}/tests

%files -n python2-%{sname}-tests
%license LICENSE
%{python2_sitelib}/%{sname}/tests

%files -n python-%{sname}-doc
%license LICENSE
%doc doc/build/html README.rst

%changelog
* Fri Aug 10 2018 Ilya Etingof <etingof@gmail.com> 0.1.0-1
- Add Python 3 build
