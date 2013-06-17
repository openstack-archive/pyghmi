#!/usr/bin/env python
from ipmi_command import ipmi_command
import os
import sys
password=os.environ['IPMIPASSWORD']
os.environ['IPMIPASSWORD']=""
if (len(sys.argv) < 3):
    print "Usage:"
    print " IPMIPASSWORD=password %s bmc username <cmd> <optarg>"%sys.argv[0]
    sys.exit(1)
bmc=sys.argv[1]
userid=sys.argv[2]
command=sys.argv[3]
arg=None
if len(sys.argv)==5:
    arg=sys.argv[4]
ipmicmd = ipmi_command(bmc=bmc,userid=userid,password=password)
if command == 'power':
    if arg:
        print ipmicmd.set_power(arg,wait=True)
    else:
        print ipmicmd.get_power()
elif command == 'bootdev':
    if arg:
        print ipmicmd.set_bootdev(arg)
    else:
        print ipmicmd.get_bootdev()
    
