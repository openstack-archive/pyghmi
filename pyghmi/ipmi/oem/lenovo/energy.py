# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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

import pyghmi.exceptions as pygexc
import struct


class EnergyManager(object):

    def __init__(self, ipmicmd):
        # there are two IANA possible for the command set, start with
        # the Lenovo, then fallback to IBM
        # We start with a 'find firmware instance' to test the water and
        # get the handle (which has always been the same, but just in case
        self.iana = bytearray('\x66\x4a\x00')
        try:
            rsp = ipmicmd.xraw_command(netfn=0x2e, command=0x82,
                                       data=self.iana + '\x00\x00\x01')
        except pygexc.IpmiException as ie:
            if ie.ipmicode == 193:  # try again with IBM IANA
                self.iana = bytearray('\x4d\x4f\x00')
                rsp = ipmicmd.xraw_command(netfn=0x2e, command=0x82,
                                           data=self.iana + '\x00\x00\x01')
            else:
                raise
        if rsp['data'][4:6] not in (b'\x02\x01', b'\x02\x06', b'\x02\x09'):
            raise pygexc.UnsupportedFunctionality(
                "Energy Control {0}.{1} not recognized".format(rsp['data'][4],
                                                               rsp['data'][5]))
        self.modhandle = bytearray(rsp['data'][6:7])
        if self.get_ac_energy(ipmicmd):
            self.supportedmeters = ('AC Energy', 'DC Energy')
        else:
            self.supportedmeters = ('DC Energy',)

    def get_energy_precision(self, ipmicmd):
        rsp = ipmicmd.xraw_command(
            netfn=0x2e, command=0x81,
            data=self.iana + self.modhandle + b'\x01\x80')
        print(repr(rsp['data'][:]))

    def get_ac_energy(self, ipmicmd):
        try:
            rsp = ipmicmd.xraw_command(
                netfn=0x2e, command=0x81,
                data=self.iana + self.modhandle + b'\x01\x82\x01\x08')
            # data is in millijoules, convert to the more recognizable kWh
            return float(
                struct.unpack('!Q', rsp['data'][3:])[0]) / 1000000 / 3600
        except pygexc.IpmiException as ie:
            if ie.ipmicode == 0xcb:
                return 0.0
            raise

    def get_dc_energy(self, ipmicmd):
        rsp = ipmicmd.xraw_command(
            netfn=0x2e, command=0x81,
            data=self.iana + self.modhandle + b'\x01\x82\x00\x08')
        # data is in millijoules, convert to the more recognizable kWh
        return float(struct.unpack('!Q', rsp['data'][3:])[0]) / 1000000 / 3600


if __name__ == '__main__':
    import os
    import pyghmi.ipmi.command as cmd
    import sys
    c = cmd.Command(sys.argv[1], os.environ['BMCUSER'], os.environ['BMCPASS'])
    EnergyManager(c).get_dc_energy(c)
