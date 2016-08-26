# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

import struct

import pyghmi.constants as const
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.sdr as sdr

aem_cmds = {
    "fw power cap reg": {
        "netfn": 0x2e,
        "command": 0x81,
        "data": [0x4d, 0x4f, 0x00, 0x00, 0x00, 0x82, 0x07, 0x01]},
    "extend fw cap reg": {
        "netfn": 0x2e,
        "command": 0x81,
        "data": [0x4d, 0x4f, 0x00, 0x00, 0x00, 0x82, 0x0e, 0x04]},
    "element config": {
        "netfn": 0x2e,
        "command": 0x81,
        "data": [0x4d, 0x4f, 0x00, 0x00, 0x03, 0x80]},
    "find fw instance": {
        "netfn": 0x2e,
        "command": 0x82,
        "data": [0x4d, 0x4f, 0x00, 0x00, 0x00, 0x01]},
    "read snapshot buffer": {
        "netfn": 0x2e,
        "command": 0x81,
        "data": [0x4d, 0x4f, 0x00, 0x00, 0x03, 0x81, 0x00, 0x00, 0x00, 0xe0]},
}


class Energy(object):

    def __init__(self, ipmicmd):
        # variable for the aem capability
        self.has_timestamp = False
        self.ipmicmd = ipmicmd
        self.handle = self._get_handle()
        self.cpu_power = None
        self.memory_power = None
        self.timestamp = None

    def _get_handle(self):
        rsp = self.ipmicmd.xraw_command(**aem_cmds["find fw instance"])
        return ord(rsp['data'][6])

    @property
    def has_subsystem_metering(self):
        try:
            # get the firmware Power/Thermal capability register
            fw_cap = self.read_element_register(
                self.handle,
                aem_cmds["fw power cap reg"]
            )
            if ord(fw_cap[0]) & 0x80:
                # get the extended firmware capability register
                fw_ext = self.read_element_register(
                    self.handle,
                    aem_cmds["extend fw cap reg"]
                )
                if ord(fw_ext[3]) & 0x10:
                    self.has_timestamp = True

                if ord(fw_ext[3]) & 0x20:
                    return True
        except Exception:
            return False

        return False

    def read_element_register(self, handle, command):
        """read the element register
        """
        command['data'][3] = handle
        rsp = self.ipmicmd.xraw_command(**command)
        return rsp['data'][3:]

    def read_element_configuration(self, command, handle, elementID=3):
        """read the element configuration

        @param command: command used to read the element
        @param handle: module handle for the aem fw
        @param elementID: element ID to read the configuration

        @return: tuple of the data length and configuration data
        """
        command['data'][3] = handle
        command['data'][4] = elementID
        rsp = self.ipmicmd.xraw_command(**command)
        return ord(rsp['data'][3]), rsp['data'][5:]

    def read_snapshot_buffer(self):
        if not self.has_subsystem_metering:
            return []

        length, config = self.read_element_configuration(
            aem_cmds["element config"],
            self.handle
        )

        buffer_size = struct.unpack('>H', config[0:2])[0]
        total_size = struct.unpack('>H', config[4:6])[0]

        offset = 0
        snapshot_buffer = []
        command = aem_cmds["read snapshot buffer"]
        command['data'][3] = self.handle
        command['data'][6] = 0x00
        command['data'][7] = 0x00
        command['data'][8] = buffer_size >> 8 & 0xff
        command['data'][9] = buffer_size & 0xff

        buffer_tag, prior_buffer_tag = None, None

        while offset < total_size:
            try:
                rsp = self.ipmicmd.xraw_command(**command)
            except pygexc.IpmiException, ie:
                if ie.ipmicode in (202, 204):
                    # if the number of requested bytes cannot be returned,
                    # reduce the size
                    command['data'][9] = command['data'][9] / 2
                    continue
                else:
                    raise
            buffer_tag = rsp['data'][3:5]

            if prior_buffer_tag and not buffer_tag == prior_buffer_tag:
                # reset the offset to beginning if the snapshot is updated in
                # the reading
                offset = 0
                snapshot_buffer = []
                buffer_tag, prior_buffer_tag = None, None
            else:
                offset += struct.unpack('>H', rsp['data'][5:7])[0]
                snapshot_buffer.extend(rsp['data'][7:])
                prior_buffer_tag = buffer_tag

            command['data'][6] = offset >> 8 & 0xff
            command['data'][7] = offset & 0xff

            if total_size - offset < buffer_size:
                command['data'][9] = total_size - offset
            else:
                command['data'][8] = buffer_size >> 8 & 0xff
                command['data'][9] = buffer_size & 0xff

        return snapshot_buffer

    def get_energy_sensor(self):
        snapshot_buffer = self.read_snapshot_buffer()

        # search the metering data if server supports subsystem power metering
        if self.has_subsystem_metering and len(snapshot_buffer) > 37:
            start = len(snapshot_buffer) - 37
            found_cpu_power = False
            found_mem_power = False

            # search the pattern from tail only for CPU(0)/MEM(1)/PSU(2)/FAN(3)
            for i in range(4):

                # metering data start from:
                # count (1 byte),
                # subsystem type (1 byte),
                # subsystem power metering (8 bytes)...
                if ord(snapshot_buffer[start + i*9]) == 4-i:
                    found_subsystem = True
                    sub_start = start + 1 + i*9
                    for j in range(4-i):
                        ordValue = ord(snapshot_buffer[sub_start + j*9])
                        if ordValue not in (1, 2, 3, 4):
                            found_subsystem = False
                            break

                    if found_subsystem:
                        start = start + i*9
                        index = 0
                        while index < ord(snapshot_buffer[start]):
                            # CPU power metering
                            ordValue = ord(snapshot_buffer[start+1+index*9])
                            if ordValue == 0x01:
                                tmp = ''.join(
                                    snapshot_buffer[
                                        start+2+index*9:start+10+index*9
                                    ])
                                self.cpu_power = struct.unpack('>Q', tmp)[0]
                                found_cpu_power = True
                            # Memory power metering
                            elif ordValue == 0x02:
                                tmp = ''.join(
                                    snapshot_buffer[
                                        start+2+index*9:start+10+index*9
                                    ])
                                self.memory_power = struct.unpack('>Q', tmp)[0]
                                found_mem_power = True
                            index += 1

                        if self.has_timestamp:
                            tmp = ''.join(snapshot_buffer[start-8:start])
                            self.timestamp = struct.unpack('>Q', tmp)[0]
                        break

            # mimic the power sensor
            if found_cpu_power and self.timestamp:
                tmp = {
                    'name': "CPU Energy",
                    'health': const.Health.Ok,
                    'states': [],
                    'state_ids': [self.timestamp],
                    'type': "Current",
                    'units': "millijoule",
                    'value': self.cpu_power,
                    'imprecision': None
                }
                yield(sdr.SensorReading(tmp, tmp['units']))

            if found_mem_power and self.timestamp:
                tmp = {
                    'name': "MEM Energy",
                    'health': const.Health.Ok,
                    'states': [],
                    'state_ids': [self.timestamp],
                    'type': "Current",
                    'units': "millijoule",
                    'value': self.memory_power,
                    'imprecision': None
                }
                yield(sdr.SensorReading(tmp, tmp['units']))
