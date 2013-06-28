#!/usr/bin/env python

from setuptools import setup

setup(name='python-ipmi',
      version='0.1.11',
      description='Python IPMI implementation',
      author='Jarrod Johnson',
      author_email='jbjohnso@us.ibm.com',
      url='http://xcat.sf.net/',
      install_requires=['pycrypto'],
      packages=['ipmi','ipmi.private'],
     )
