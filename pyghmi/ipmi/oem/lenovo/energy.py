# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015 Lenovo
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

import pyghmi.constants as const
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.sdr as sdr


class Energy(object):
    def __init__(self, ipmicmd):
        self.ipmicmd = ipmicmd

    def get_energy_sensor(self):
        """read the cpu usage
        """
        try:
            rsp = self.ipmicmd.xraw_command(
                netfn=0x04,
                command=0x2d,
                bridge_request={"addr": 0x2c, "channel": 0x06}, data=[0xbe]
            )
        except pygexc.IpmiException:
            return

        cpu_usage = ord(rsp["data"][0]) * 100 / 0xff

        # mimic the power sensor
        temp = {
            'name': "CPU_Usage",
            'health': const.Health.Ok,
            'states': [],
            'state_ids': [],
            'type': "Processor",
            'units': "%",
            'value': cpu_usage,
            'imprecision': None
        }
        yield(sdr.SensorReading(temp, temp['units']))
