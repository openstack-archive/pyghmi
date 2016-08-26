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

import os
import re
import struct
import time

import pyghmi.exceptions as pygexc
import pyghmi.ipmi.oem.generic as generic

from pyghmi.ipmi.oem.ibm import aem
from pyghmi.ipmi.oem.ibm import fetchffdc
from pyghmi.ipmi.oem.ibm import smbios


led_state = {
    0x00: "Off",
    0xFF: "On"
}
led_state_default = "Blink"

led_color = {
    0x01: 'Red',
    0x02: 'Orange',
    0x04: 'Yellow',
    0x08: 'Green',
    0x10: 'Blue',
    0x20: 'White'
}
led_color_default = "Unknown"

led_location = {
    0x01: 'Front Panel',
    0x02: 'Lightpath Card',
    0x04: 'System Board',
    0x08: 'FRU',
    0x10: 'MEU (Memory Expansion Unit)',
    0x80: 'Rear Panel'
}
led_location_default = "Front Panel"


class OEMHandler(generic.OEMHandler):

    # noinspection PyUnusedLocal
    def __init__(self, oemid, ipmicmd):
        # will need to retain data to differentiate
        # variations.  For example System X versus Thinkserver
        self.oemid = oemid
        self.ipmicmd = ipmicmd
        self.oem_inventory_info = None
        self.smbios_table = None

    @property
    def has_imm(self):
        """True if this particular server is IMM based server
        """
        if (self.oemid['manufacturer_id'] in (2, 20301) and
                self.oemid['device_id'] == 32):
            try:
                self.ipmicmd.xraw_command(netfn=0x3a, command=0x00)
            except pygexc.IpmiException as ie:
                if ie.ipmicode == 193:
                    return False
                raise
            return True
        return False

    def get_oem_inventory_descriptions(self):
        if self.has_imm:
            if not self.oem_inventory_info:
                self._collect_imm_inventory()
            return iter(self.oem_inventory_info)
        return ()

    def get_oem_inventory(self):
        if self.has_imm:
            self._collect_imm_inventory()
            for compname in self.oem_inventory_info:
                yield (compname, self.oem_inventory_info[compname])

    def get_inventory_of_component(self, component):
        if self.has_imm:
            self._collect_imm_inventory()
            return self.oem_inventory_info.get(component, None)

    def _get_smbios_table(self):
        raw_info = smbios.get_smbios_info(self.ipmicmd)
        if raw_info:
            self.smbios_table = smbios.parse_smbios_info(raw_info)

    def _collect_imm_inventory(self):
        self.oem_inventory_info = {}
        if self.smbios_table is None:
            self._get_smbios_table()
        for item in self.smbios_table:
            if item.get('Type') and item['Type'] == 'CPU':
                self.oem_inventory_info['CPU ' + item['Socket'][-1]] = item

    def get_leds(self):
        """Get the led status for System x server

        @return: tuple - led name and dict about the led state/color/location
        """
        if self.has_imm:
            # enumerate the sdr list
            sdr_list = self._get_oem_sdr_list()
            for item in sdr_list:
                # identifies this OEM record as an LED record
                if ord(item[8]) == 0xed:
                    try:
                        led_identifier = struct.unpack('2B', item[11:13])
                        led_name = item[15:].rstrip('\x00')
                        # get the led status
                        rsp = self.ipmicmd.xraw_command(
                            netfn=0x3A,
                            command=0xc0,
                            data=led_identifier
                        )
                    except pygexc.IpmiException:
                        # ignore LEDs we can't retrieve
                        continue

                    state = led_state.get(
                        ord(rsp['data'][1]),
                        led_state_default
                    )
                    color = led_color.get(
                        ord(rsp['data'][0]),
                        led_color_default
                    )
                    location = led_location.get(
                        ord(item[14]),
                        led_location_default
                    )
                    yield (
                        led_name, {
                            'status': state,
                            'color': color,
                            'location': location
                        })

    def process_fru(self, fru):
        if fru is None:
            return fru

        if self.has_imm:
            fru['oem_parser'] = 'ibm'
            # exclude the CPU FRU as it is retrieved from SMBIOS
            vals = fru.values()
            for val in vals:
                if isinstance(val, basestring):
                    if re.match(r'.*(cpu|processor).*', val, re.IGNORECASE):
                        return None
            return fru
        else:
            fru['oem_parser'] = None
            return fru

    def get_oem_firmware(self):
        if self.has_imm:
            fw_info = []
            # add the firmware info in the SMBIOS table, can not cache it as FW
            # might be upgraded
            self._get_smbios_table()
            for item in self.smbios_table:
                if item['Type'] == 'BIOS':
                    fw_info.append(('UEFI', {'version': item['Version']}))
                if item['Type'] == 'OEM Strings':
                    for oem_string in item['OEM Strings']:
                        # search the IMM version
                        for ver in ('1AOO', 'TCOO', 'YUOO'):
                            imm_idx = oem_string.find(ver)
                            if imm_idx != -1:
                                break
                        # search the dsa version
                        for dsa in ('DSYT', 'DSAL', 'DSY1'):
                            dsa_idx = oem_string.find(dsa)
                            if dsa_idx != -1:
                                break
                        if imm_idx != -1:
                            v1 = oem_string[imm_idx:imm_idx+7]
                            v2 = oem_string[imm_idx-7:imm_idx-3]
                            version = v1 + '-' + v2
                            fw_info.append(('IMM', {'version': version}))
                        if dsa_idx != -1:
                            v3 = oem_string[dsa_idx:dsa_idx+7]
                            v4 = oem_string[dsa_idx-7:dsa_idx-3]
                            version = v3 + '-' + v4
                            fw_info.append(('DSA', {'version': version}))
            return fw_info
        return ()

    def get_oem_service_log(self):
        if self.has_imm:
            timestamp = bytes(time.time()).split('.')[0]
            filename = 'var/log/ffdc_' + timestamp + '.tgz'
            dir_name = os.path.dirname(filename)
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
            ffdc_fetcher = fetchffdc.FFDCFetcher(self.ipmicmd)
            ret = ffdc_fetcher.fetch_ffdc_file(filename)
            if ret:
                return ({'FFDC': os.path.abspath(filename)})
        return ()

    def get_oem_remote_kvm_available(self):
        if self.has_imm:
            rsp = self.ipmicmd.raw_command(netfn=0x3a, command=0xc1)
            return not bool(rsp['data'][0] & 0x40)
        return False

    def get_oem_identifier(self):
        if self.has_imm:
            name = ''
            rsp = self.ipmicmd.xraw_command(netfn=0x3a, command=0x55)
            name += rsp['data'][:]
            return name.rstrip('\x00')

    def set_oem_identifier(self, name):
        if self.has_imm:
            data = []
            data.extend([ord(x) for x in name])
            # set the domain name content
            if len(name) < 64:
                data.extend([0])
            else:
                data[64] = 0

            self.ipmicmd.xraw_command(netfn=0x3a, command=0x55, data=data)
            return True
        return False

    def _get_oem_sdr_list(self):
        if self.has_imm:
            sdr_list = []
            data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x20]
            last_sdr = False
            while True:
                try:
                    rsp = self.ipmicmd.xraw_command(
                        netfn=0x0a,
                        command=0x23,
                        data=data
                    )
                except pygexc.IpmiException, ie:
                    if ie.ipmicode in (202, 204):
                        # if the number of requested bytes cannot be returned,
                        # reduce the size
                        data[5] = data[5] - 2
                        continue
                if ord(rsp['data'][5]) == 0xc0:
                    sdr_list.append(rsp['data'][2:])
                if last_sdr:
                    break
                data[2] = ord(rsp['data'][0])
                data[3] = ord(rsp['data'][1])
                data[5] = 0x20
                if ord(rsp['data'][0]) == 0xff:
                    if ord(rsp['data'][1]) == 0xff:
                        last_sdr = True
            return sdr_list

    def get_sensor_reading(self, sensorname):
        """Get an OEM sensor

        If software wants to model some OEM behavior as a 'sensor' without
        doing SDR, this hook provides that ability.  It should mimic
        the behavior of 'get_sensor_reading' in command.py.
        """
        for sensor in self.get_sensor_data():
            if sensor.name == sensorname:
                return sensor

    def get_sensor_descriptions(self):
        """Get list of OEM sensor names and types

        Iterate over dicts describing a label and type for OEM 'sensors'.  This
        should mimic the behavior of the get_sensor_descriptions function
        in command.py.
        """
        if self.has_imm:
            energy_sensor = aem.Energy(self.ipmicmd)
            for sensor in energy_sensor.get_energy_sensor():
                yield {'name': sensor.name,
                       'type': sensor.type}

    def get_sensor_data(self):
        """Get OEM sensor data

        Iterate through all OEM 'sensors' and return data as if they were
        normal sensors.  This should mimic the behavior of the get_sensor_data
        function in command.py.
        """
        if self.has_imm:
            energy_sensor = aem.Energy(self.ipmicmd)
            for sensor in energy_sensor.get_energy_sensor():
                yield sensor

    def get_extra_net_configuration(self):
        ipv6_addr = self.ipmicmd.xraw_command(
            netfn=0x0c,
            command=0x02,
            data=(0x01, 0xc8, 0x00, 0x00)
        )["data"][2:]

        if not ipv6_addr:
            return '::'

        bytes = [format(ord(a), '02x') for a in ipv6_addr]
        bytes = zip(bytes[0::2], bytes[1::2])
        ipv6_addr = ':'.join([b[0] + b[1] for b in bytes])
        return {"ipv6_addr": ipv6_addr}
