#!/usr/bin/env python
# Copyright 2013 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# """
# @author: Jarrod Johnson <jbjohnso@us.ibm.com>
# """

# """This is an example of using the library in a synchronous fashion. For now,
# it isn't conceived as a general utility to actually use, just help developers
# understand how the ipmi_command class workes.
# """
import functools
import os
import string
import sys

from pyghmi.ipmi import command


def docommand(args, result, ipmisession):
    command = args[0]
    args = args[1:]
    print("Logged into %s" % ipmisession.bmc)
    if 'error' in result:
        print(result['error'])
        return
    if command == 'power':
        if args:
            print(ipmisession.set_power(args[0], wait=True))
        else:
            value = ipmisession.get_power()
            print("%s: %s" % (ipmisession.bmc, value['powerstate']))
    elif command == 'bootdev':
        if args:
            print(ipmisession.set_bootdev(args[0]))
        else:
            print(ipmisession.get_bootdev())
    elif command == 'sensors':
        for reading in ipmisession.get_sensor_data():
            print(reading)
    elif command == 'health':
        print(ipmisession.get_health())
    elif command == 'inventory':
        for item in ipmisession.get_inventory():
            print(item)
    elif command == 'leds':
        for led in ipmisession.get_leds():
            print(led)
    elif command == 'graphical':
        print(ipmisession.get_graphical_console())
    elif command == 'net':
        print(ipmisession.get_net_configuration())
    elif command == 'raw':
        print(ipmisession.raw_command(
              netfn=int(args[0]),
              command=int(args[1]),
              data=map(lambda x: int(x, 16), args[2:])))


def main():
    if (len(sys.argv) < 3) or 'IPMIPASSWORD' not in os.environ:
        print("Usage:")
        print(" IPMIPASSWORD=password %s bmc username <cmd> <optarg>" % sys.argv[0])
        return 1

    password = os.environ['IPMIPASSWORD']
    os.environ['IPMIPASSWORD'] = ""
    bmc = sys.argv[1]
    userid = sys.argv[2]

    bmcs = string.split(bmc, ",")
    ipmicmd = None
    for bmc in bmcs:
        # NOTE(etingof): is it right to have `ipmicmd` overridden?
        ipmicmd = command.Command(
            bmc=bmc, userid=userid, password=password,
            onlogon=functools.partial(docommand, sys.argv[3:]))

    if ipmicmd:
        ipmicmd.eventloop()


if __name__ == '__main__':
    sys.exit(main())
