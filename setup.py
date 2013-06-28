#!/usr/bin/env python

from distutils.core import setup

setup(name='python-ipmi',
      version='0.1.8',
      description='Python IPMI implementation',
      author='Jarrod Johnson',
      author_email='jbjohnso@us.ibm.com',
      url='http://xcat.sf.net/',
      requires=['pycrypto'],
      packages=['ipmi'],
     )
