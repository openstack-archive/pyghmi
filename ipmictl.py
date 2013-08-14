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
import string
import sys

from pyghmi.ipmi import command
password = os.environ['IPMIPASSWORD']
os.environ['IPMIPASSWORD'] = ""
if (len(sys.argv) < 3):
    print "Usage:"
    print " IPMIPASSWORD=password %s bmc username <cmd> <optarg>" % sys.argv[0]
    sys.exit(1)
bmc = sys.argv[1]
userid = sys.argv[2]
args = None
if len(sys.argv) >= 5:
    args = sys.argv[4:]

ipmicmd = None


def docommand(result, ipmisession):
    cmmand = sys.argv[3]
    print "Logged into %s" % ipmisession.bmc
    if 'error' in result:
        print result['error']
        return
    if cmmand == 'power':
        if args:
            print ipmisession.set_power(args[0], wait=True)
        else:
            value = ipmisession.get_power()
            print "%s: %s" % (ipmisession.bmc, value['powerstate'])
    elif cmmand == 'bootdev':
        if args:
            print ipmisession.set_bootdev(args[0])
        else:
            print ipmisession.get_bootdev()
    elif cmmand == 'raw':
        print ipmisession.raw_command(netfn=int(args[0]),
                                      command=int(args[1]),
                                      data=map(lambda x: int(x, 16), args[2:]))

bmcs = string.split(bmc, ",")
for bmc in bmcs:
    ipmicmd = command.Command(bmc=bmc, userid=userid, password=password,
                              onlogon=docommand)
ipmicmd.eventloop()
