#!/usr/bin/env python
"""
@author: Jarrod Johnson <jbjohnso@us.ibm.com>

Copyright 2013 IBM Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""This is an example of using the library in a synchronous fashion. For now,
it isn't conceived as a general utility to actually use, just help developers
understand how the ipmi_command class workes.
"""
import os
import sys

from ipmi.command import Command
password = os.environ['IPMIPASSWORD']
os.environ['IPMIPASSWORD'] = ""
if (len(sys.argv) < 3):
    print "Usage:"
    print " IPMIPASSWORD=password %s bmc username <cmd> <optarg>" % sys.argv[0]
    sys.exit(1)
bmc = sys.argv[1]
userid = sys.argv[2]
command = sys.argv[3]
args = None
if len(sys.argv) >= 5:
    args = sys.argv[4:]
ipmicmd = Command(bmc=bmc, userid=userid, password=password)
if command == 'power':
    if args[0]:
        print ipmicmd.set_power(arg, wait=True)
    else:
        print ipmicmd.get_power()
elif command == 'bootdev':
    if args[0]:
        print ipmicmd.set_bootdev(arg)
    else:
        print ipmicmd.get_bootdev()
elif command == 'raw':
    netfn = args[0]
    command = args[1]
    data = args[2:]
    print ipmicmd.raw_command(netfn=netfn, command=command, data=data)
