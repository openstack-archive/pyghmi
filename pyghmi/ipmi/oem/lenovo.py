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

import pyghmi.constants as pygconst
import pyghmi.ipmi.oem.generic as generic
import pyghmi.ipmi.private.constants as ipmiconst
import pyghmi.ipmi.private.spd as spd
import pyghmi.ipmi.private.util as util
import struct

firmware_types = {
    1: 'Management Controller',
    2: 'UEFI/BIOS',
    3: 'CPLD',
    4: 'Power Supply',
    5: 'Storage Adapter',
    6: 'Add-in Adapter',
}

firmware_event = {
    0: ('Update failed', pygconst.Health.Failed),
    1: ('Update succeeded', pygconst.Health.Ok),
    2: ('Update aborted', pygconst.Health.Ok),
    3: ('Unknown', pygconst.Health.Warning),
}

me_status = {
    0: ('Recovery GPIO forced', pygconst.Health.Warning),
    1: ('ME Image corrupt', pygconst.Health.Critical),
    2: ('Flash erase error', pygconst.Health.Critical),
    3: ('Unspecified flash state', pygconst.Health.Warning),
    4: ('ME watchdog timeout', pygconst.Health.Critical),
    5: ('ME platform reboot', pygconst.Health.Critical),
    6: ('ME update', pygconst.Health.Ok),
    7: ('Manufacturing error', pygconst.Health.Critical),
    8: ('ME Flash storage integrity error', pygconst.Health.Critical),
    9: ('ME firmware exception', pygconst.Health.Critical),  # event data 3..
    0xa: ('ME firmware worn', pygconst.Health.Warning),
    0xc: ('Invalid SCMP state', pygconst.Health.Warning),
    0xd: ('PECI over DMI failure', pygconst.Health.Warning),
    0xe: ('MCTP interface failure', pygconst.Health.Warning),
    0xf: ('Auto configuration completed', pygconst.Health.Ok),
}

me_flash_status = {
    0: ('ME flash corrupted', pygconst.Health.Critical),
    1: ('ME flash erase limit reached', pygconst.Health.Critical),
    2: ('ME flash write limit reached', pygconst.Health.Critical),
    3: ('ME flash write enabled', pygconst.Health.Ok),
}


class OEMHandler(generic.OEMHandler):
    # noinspection PyUnusedLocal
    def __init__(self, oemid, ipmicmd):
        # will need to retain data to differentiate
        # variations.  For example System X versus Thinkserver
        self.oemid = oemid
        self.ipmicmd = ipmicmd
        self.oem_inventory_info = None

    def process_event(self, event, ipmicmd, seldata):
        if 'oemdata' in event:
            oemtype = seldata[2]
            oemdata = event['oemdata']
            if oemtype == 0xd0:  # firmware update
                event['component'] = firmware_types.get(oemdata[0], None)
                event['component_type'] = ipmiconst.sensor_type_codes[0x2b]
                slotnumber = (oemdata[1] & 0b11111000) >> 3
                if slotnumber:
                    event['component'] += ' {0}'.format(slotnumber)
                event['event'], event['severity'] = \
                    firmware_event[oemdata[1] & 0b111]
                event['event_data'] = '{0}.{1}'.format(oemdata[2], oemdata[3])
            elif oemtype == 0xd1:  # BIOS recovery
                event['severity'] = pygconst.Health.Warning
                event['component'] = 'BIOS/UEFI'
                event['component_type'] = ipmiconst.sensor_type_codes[0xf]
                status = oemdata[0]
                method = (status & 0b11110000) >> 4
                status = (status & 0b1111)
                if method == 1:
                    event['event'] = 'Automatic recovery'
                elif method == 2:
                    event['event'] = 'Manual recovery'
                if status == 0:
                    event['event'] += '- Failed'
                    event['severity'] = pygconst.Health.Failed
                if oemdata[1] == 0x1:
                    event['event'] += '- BIOS recovery image not found'
                event['event_data'] = '{0}.{1}'.format(oemdata[2], oemdata[3])
            elif oemtype == 0xd2:  # eMMC status
                if oemdata[0] == 1:
                    event['component'] = 'eMMC'
                    event['component_type'] = ipmiconst.sensor_type_codes[0xc]
                    if oemdata[0] == 1:
                        event['event'] = 'eMMC Format error'
                        event['severity'] = pygconst.Health.Failed
            elif oemtype == 0xd3:
                if oemdata[0] == 1:
                    event['event'] = 'User privilege modification'
                    event['severity'] = pygconst.Health.Ok
                    event['component'] = 'User Privilege'
                    event['component_type'] = ipmiconst.sensor_type_codes[6]
                    event['event_data'] = \
                        'User {0} on channel {1} had privilege changed ' \
                        'from {2} to {3}'.format(
                            oemdata[2], oemdata[1], oemdata[3] & 0b1111,
                            (oemdata[3] & 0b11110000) >> 4
                        )
            else:
                event['event'] = 'OEM event: {0}'.format(
                    ' '.join(format(x, '02x') for x in event['oemdata']))
            del event['oemdata']
            return
        evdata = event['event_data_bytes']
        if event['event_type_byte'] == 0x75:  # ME event
            event['component'] = 'ME Firmware'
            event['component_type'] = ipmiconst.sensor_type_codes[0xf]
            event['event'], event['severity'] = me_status.get(
                evdata[1], ('Unknown', pygconst.Health.Warning))
            if evdata[1] == 3:
                event['event'], event['severity'] = me_flash_status.get(
                    evdata[2], ('Unknown state', pygconst.Health.Warning))
            elif evdata[1] == 9:
                event['event'] += ' (0x{0:2x})'.format(evdata[2])
            elif evdata[1] == 0xf and evdata[2] & 0b10000000:
                event['event'] = 'Auto configuration failed'
                event['severity'] = pygconst.Health.Critical
        # For HDD bay events, the event data 2 is the bay, modify
        # the description to be more specific
        if (event['event_type_byte'] == 0x6f and
                (evdata[0] & 0b11000000) == 0b10000000 and
                event['component_type_id'] == 13):
            event['component'] += ' {0}'.format(evdata[1] & 0b11111)

    @property
    def has_tsm(self):
        """True if this particular server have a TSM based service processor
        """
        return (self.oemid['manufacturer_id'] == 19046 and
                self.oemid['device_id'] == 32)

    def get_oem_inventory_descriptions(self):
        if self.has_tsm:
            # Thinkserver with TSM
            if not self.oem_inventory_info:
                self._collect_tsm_inventory()
            return iter(self.oem_inventory_info)
        return ()

    def get_oem_inventory(self):
        if self.has_tsm:
            self._collect_tsm_inventory()
            for compname in self.oem_inventory_info:
                yield (compname, self.oem_inventory_info[compname])

    def get_inventory_of_component(self, component):
        if self.has_tsm:
            self._collect_tsm_inventory()
            return self.oem_inventory_info.get(component, None)

    def _decode_tsm_cpu(self, offset, cpudata):
        keytext = 'CPU {0}'.format(ord(cpudata[offset]))
        self.oem_inventory_info[keytext] = {}
        if cpudata[offset + 1] == '\x00':
            self.oem_inventory_info[keytext] = None
            return
        self.oem_inventory_info[keytext]['cores'] = ord(
            cpudata[offset + 1])
        self.oem_inventory_info[keytext]['threads'] = ord(
            cpudata[offset + 2])
        self.oem_inventory_info[keytext]['manufacturer'] = \
            cpudata[offset + 3:offset + 16].rstrip('\x00')
        self.oem_inventory_info[keytext]['family'] = \
            cpudata[offset + 16: offset + 46].rstrip('\x00')
        self.oem_inventory_info[keytext]['model'] = \
            cpudata[offset + 46: offset + 76].rstrip('\x00')
        self.oem_inventory_info[keytext]['stepping'] = \
            cpudata[offset + 76: offset + 79].rstrip('\x00')
        self.oem_inventory_info[keytext]['frequency'] = \
            '{0:.1f} GHz'.format(
                struct.unpack('<I',
                              cpudata[offset + 79: offset + 83])[0] / 1000.0)

    def _decode_tsm_dimm(self, offset, memdata):
        keytext = 'DIMM {0}'.format(ord(memdata[offset]))
        if memdata[offset + 1] == '\x00':
            self.oem_inventory_info[keytext] = None
            return
        self.oem_inventory_info[keytext] = {}
        self.oem_inventory_info[keytext]['module_type'] = \
            memdata[offset + 3: offset + 13].rstrip('\x00')
        self.oem_inventory_info[keytext]['voltage'] = \
            memdata[offset + 13: offset + 23].rstrip('\x00')
        clock = struct.unpack(
            '<H', memdata[offset + 23:offset + 25])[0]
        self.oem_inventory_info[keytext]['speed'] = spd.speed_by_clock.get(
            clock, 'Unknown')
        self.oem_inventory_info[keytext]['capacity_mb'] = struct.unpack(
            '<H', memdata[offset + 25:offset + 27])[0] * 1024
        self.oem_inventory_info[keytext]['manufacturer'] = \
            memdata[offset + 27:offset + 57].rstrip('\x00')
        self.oem_inventory_info[keytext]['serial'] = \
            struct.unpack('>I', memdata[offset + 57:offset + 61])[0]
        self.oem_inventory_info[keytext]['model'] = \
            memdata[offset + 61:offset + 82].rstrip('\x00')

    def _collect_tsm_inventory(self):
        # Collect CPU inventory
        self.oem_inventory_info = {}
        rsp = self.ipmicmd.xraw_command(netfn=6, command=0x59,
                                        data=(0, 0xc1, 1, 0))
        compcount = ord(rsp['data'][1])
        for cpu in xrange(0, compcount):
            offset = 2 + (85 * cpu)
            self._decode_tsm_cpu(offset, rsp['data'])
        # Collect memory inventory
        rsp = self.ipmicmd.xraw_command(netfn=6, command=0x59,
                                        data=(0, 0xc1, 2, 0))
        compcount = ord(rsp['data'][1])
        for dimm in xrange(0, compcount):
            offset = 2 + (dimm * 84)
            self._decode_tsm_dimm(offset, rsp['data'])

    def process_fru(self, fru):
        if fru is None:
            return fru
        if self.has_tsm:
            fru['oem_parser'] = 'lenovo'
            # Thinkserver lays out specific interpretation of the
            # board extra fields
            _, _, wwn1, wwn2, mac1, mac2 = fru['board_extra']
            if wwn1 not in ('0000000000000000', ''):
                fru['WWN 1'] = wwn1
            if wwn2 not in ('0000000000000000', ''):
                fru['WWN 2'] = wwn2
            if mac1 not in ('00:00:00:00:00:00', ''):
                fru['MAC Address 1'] = mac1
            if mac2 not in ('00:00:00:00:00:00', ''):
                fru['MAC Address 2'] = mac2
            try:
                # The product_extra field is UUID as the system would present
                # in DMI.  This is different than the two UUIDs that
                # it returns for get device and get system uuid...
                byteguid = fru['product_extra'][0]
                # It can present itself as claiming to be ASCII when it
                # is actually raw hex.  As a result it triggers the mechanism
                # to strip \x00 from the end of text strings.  Work around this
                # by padding with \x00 to the right if less than 16 long
                byteguid.extend('\x00' * (16 - len(byteguid)))
                fru['UUID'] = util.decode_wireformat_uuid(byteguid)
            except (AttributeError, KeyError):
                pass
            return fru
        else:
            fru['oem_parser'] = None
            return fru
