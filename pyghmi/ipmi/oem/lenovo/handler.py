# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015-2016 Lenovo
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

import base64
import binascii
import traceback
import urllib

import pyghmi.constants as pygconst
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.oem.generic as generic
import pyghmi.ipmi.private.constants as ipmiconst
import pyghmi.ipmi.private.util as util

from pyghmi.ipmi.oem.lenovo import cpu
from pyghmi.ipmi.oem.lenovo import dimm
from pyghmi.ipmi.oem.lenovo import drive

from pyghmi.ipmi.oem.lenovo import firmware
from pyghmi.ipmi.oem.lenovo import imm
from pyghmi.ipmi.oem.lenovo import inventory
from pyghmi.ipmi.oem.lenovo import nextscale
from pyghmi.ipmi.oem.lenovo import pci
from pyghmi.ipmi.oem.lenovo import psu
from pyghmi.ipmi.oem.lenovo import raid_controller
from pyghmi.ipmi.oem.lenovo import raid_drive


import pyghmi.util.webclient as wc

import socket
import struct
import weakref

inventory.register_inventory_category(cpu)
inventory.register_inventory_category(dimm)
inventory.register_inventory_category(pci)
inventory.register_inventory_category(drive)
inventory.register_inventory_category(psu)
inventory.register_inventory_category(raid_drive)
inventory.register_inventory_category(raid_controller)


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

leds = {
    "BMC_UID": 0x00,
    "BMC_HEARTBEAT": 0x01,
    "SYSTEM_FAULT": 0x02,
    "PSU1_FAULT": 0x03,
    "PSU2_FAULT": 0x04,
    "LED_FAN_FAULT_1": 0x10,
    "LED_FAN_FAULT_2": 0x11,
    "LED_FAN_FAULT_3": 0x12,
    "LED_FAN_FAULT_4": 0x13,
    "LED_FAN_FAULT_5": 0x14,
    "LED_FAN_FAULT_6": 0x15,
    "LED_FAN_FAULT_7": 0x16,
    "LED_FAN_FAULT_8": 0x17
}

led_status = {
    0x00: "Off",
    0xFF: "On"
}
led_status_default = "Blink"
mac_format = '{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}'


def _megarac_abbrev_image(name):
    if len(name) <= 16:
        return name
    return name[:16] + name[-4:]


class OEMHandler(generic.OEMHandler):
    # noinspection PyUnusedLocal
    def __init__(self, oemid, ipmicmd):
        # will need to retain data to differentiate
        # variations.  For example System X versus Thinkserver
        self.oemid = oemid
        self.ipmicmd = weakref.proxy(ipmicmd)
        self._has_megarac = None
        self.oem_inventory_info = None
        self._mrethidx = None
        self._hasimm = None

    @property
    def _megarac_eth_index(self):
        if self._mrethidx is None:
            chan = self.ipmicmd.get_network_channel()
            rsp = self.ipmicmd.xraw_command(0x32, command=0x62, data=(chan,))
            self._mrethidx = rsp['data'][0]
        return self._mrethidx

    def get_video_launchdata(self):
        if self.has_tsm:
            return self.get_tsm_launchdata()

    def get_tsm_launchdata(self):
        pass

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

    def get_ntp_enabled(self):
        if self.has_tsm:
            ntpres = self.ipmicmd.xraw_command(netfn=0x32, command=0xa7)
            return ntpres['data'][0] == '\x01'
        return None

    def get_ntp_servers(self):
        if self.has_tsm:
            srvs = []
            ntpres = self.ipmicmd.xraw_command(netfn=0x32, command=0xa7)
            srvs.append(ntpres['data'][1:129].rstrip('\x00'))
            srvs.append(ntpres['data'][129:257].rstrip('\x00'))
            return srvs
        return None

    def set_ntp_enabled(self, enabled):
        if self.has_tsm:
            if enabled:
                self.ipmicmd.xraw_command(
                    netfn=0x32, command=0xa8, data=(3, 1), timeout=15)
            else:
                self.ipmicmd.xraw_command(
                    netfn=0x32, command=0xa8, data=(3, 0), timeout=15)
            return True
        return None

    def set_ntp_server(self, server, index=0):
        if self.has_tsm:
            if not (0 <= index <= 1):
                raise pygexc.InvalidParameterValue("Index must be 0 or 1")
            cmddata = bytearray((1 + index, ))
            cmddata += server.ljust(128, '\x00')
            self.ipmicmd.xraw_command(netfn=0x32, command=0xa8, data=cmddata)
            return True
        return None

    @property
    def is_fpc(self):
        """True if the target is a Lenovo nextscale fan power controller
        """
        fpc_ids = ((19046, 32, 1063))
        return (self.oemid['manufacturer_id'], self.oemid['device_id'],
                self.oemid['product_id']) in fpc_ids

    @property
    def has_tsm(self):
        """True if this particular server have a TSM based service processor
        """
        if (self.oemid['manufacturer_id'] == 19046 and
                self.oemid['device_id'] == 32):
            try:
                self.ipmicmd.xraw_command(netfn=0x3a, command=0xf)
            except pygexc.IpmiException as ie:
                if ie.ipmicode == 193:
                    return False
                raise
            return True
        return False

    def get_oem_inventory_descriptions(self):
        if self.has_tsm:
            # Thinkserver with TSM
            if not self.oem_inventory_info:
                self._collect_tsm_inventory()
            return iter(self.oem_inventory_info)
        elif self.has_imm:
            return imm.get_hw_descriptions(self.ipmicmd, self._certverify)
        return ()

    def get_oem_inventory(self):
        if self.has_tsm:
            self._collect_tsm_inventory()
            for compname in self.oem_inventory_info:
                yield (compname, self.oem_inventory_info[compname])
        elif self.has_imm:
            for inv in imm.get_hw_inventory(self.ipmicmd, self._certverify):
                yield inv

    def get_sensor_data(self):
        if self.is_fpc:
            for name in nextscale.get_sensor_names():
                yield nextscale.get_sensor_reading(name, self.ipmicmd)

    def get_sensor_descriptions(self):
        if self.is_fpc:
            return nextscale.get_sensor_descriptions()
        return ()

    def get_sensor_reading(self, sensorname):
        if self.is_fpc:
            return nextscale.get_sensor_reading(sensorname, self.ipmicmd)
        return ()

    def get_inventory_of_component(self, component):
        if self.has_tsm:
            self._collect_tsm_inventory()
            return self.oem_inventory_info.get(component, None)
        if self.has_imm:
            return imm.get_component_inventory(self.ipmicmd, self._certverify,
                                               component)

    def _collect_tsm_inventory(self):
        self.oem_inventory_info = {}
        for catid, catspec in inventory.categories.items():
            if (catspec.get("workaround_bmc_bug", False)):
                rsp = None
                tmp_command = dict(catspec["command"])
                tmp_command["data"] = list(tmp_command["data"])
                count = 0
                for i in xrange(0x01, 0xff):
                    tmp_command["data"][-1] = i
                    try:
                        partrsp = self.ipmicmd.xraw_command(**tmp_command)
                        if rsp is None:
                            rsp = partrsp
                            rsp["data"] = list(rsp["data"])
                        else:
                            rsp["data"].extend(partrsp["data"][1:])
                        count += 1
                    except Exception:
                        break
                # If we didn't get any response, assume we don't have
                # this category and go on to the next one
                if rsp is None:
                    continue
                rsp["data"].insert(1, count)
                rsp["data"] = buffer(bytearray(rsp["data"]))
            else:
                try:
                    rsp = self.ipmicmd.xraw_command(**catspec["command"])
                except pygexc.IpmiException:
                    continue
            # Parse the response we got
            try:
                items = inventory.parse_inventory_category(
                    catid, rsp,
                    countable=catspec.get("countable", True)
                )
            except Exception:
                # If we can't parse an inventory category, ignore it
                print traceback.print_exc()
                continue

            for item in items:
                try:
                    key = catspec["idstr"].format(item["index"])
                    del item["index"]
                    self.oem_inventory_info[key] = item
                except Exception:
                    # If we can't parse an inventory item, ignore it
                    print traceback.print_exc()
                    continue

    def get_leds(self):
        if self.has_tsm:
            for (name, id_) in leds.items():
                try:
                    rsp = self.ipmicmd.xraw_command(netfn=0x3A, command=0x02,
                                                    data=(id_,))
                except pygexc.IpmiException:
                    continue  # Ignore LEDs we can't retrieve
                status = led_status.get(ord(rsp['data'][0]),
                                        led_status_default)
                yield (name, {'status': status})

    def process_fru(self, fru):
        if fru is None:
            return fru
        if self.has_tsm:
            fru['oem_parser'] = 'lenovo'
            # Thinkserver lays out specific interpretation of the
            # board extra fields
            try:
                _, _, wwn1, wwn2, mac1, mac2 = fru['board_extra']
                if wwn1 not in ('0000000000000000', ''):
                    fru['WWN 1'] = wwn1
                if wwn2 not in ('0000000000000000', ''):
                    fru['WWN 2'] = wwn2
                if mac1 not in ('00:00:00:00:00:00', ''):
                    fru['MAC Address 1'] = mac1
                if mac2 not in ('00:00:00:00:00:00', ''):
                    fru['MAC Address 2'] = mac2
            except (AttributeError, KeyError):
                pass
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
                if byteguid not in ('\x20' * 16, '\x00' * 16, '\xff' * 16):
                    fru['UUID'] = util.decode_wireformat_uuid(byteguid)
            except (AttributeError, KeyError, IndexError):
                pass
            return fru
        elif self.has_imm:
            fru['oem_parser'] = 'lenovo'
            try:
                bextra = fru['board_extra']
                fru['FRU Number'] = bextra[0]
                fru['Revision'] = bextra[4]
                macs = bextra[6]
                macprefix = None
                idx = 0
                endidx = len(macs) - 5
                macprefix = None
                while idx < endidx:
                    currmac = macs[idx:idx+6]
                    if currmac == b'\x00\x00\x00\x00\x00\x00':
                        break
                    # VPD may veer off, detect and break off
                    if macprefix is None:
                        macprefix = currmac[:3]
                    elif currmac[:3] != macprefix:
                        break
                    ms = mac_format.format(*currmac)
                    ifidx = idx / 6 + 1
                    fru['MAC Address {0}'.format(ifidx)] = ms
                    idx = idx + 6
            except (AttributeError, KeyError, IndexError):
                pass
            return fru
        else:
            fru['oem_parser'] = None
            return fru

    @property
    def has_imm(self):
        if self._hasimm is not None:
            return self._hasimm
        try:
            bdata = self.ipmicmd.xraw_command(netfn=0x3a, command=0xc1)
        except pygexc.IpmiException:
            self._hasimm = False
            return False
        if len(bdata['data'][:]) != 3:
            self._hasimm = False
            return False
        self._hasimm = ord(bdata['data'][1]) & 1 == 1
        return self._hasimm

    def get_oem_firmware(self, bmcver):
        if self.has_tsm:
            command = firmware.get_categories()["firmware"]
            rsp = self.ipmicmd.xraw_command(**command["command"])
            return command["parser"](rsp["data"])
        elif self.has_imm:
            return imm.get_firmware_inventory(self.ipmicmd, bmcver,
                                              self._certverify)
        return super(OEMHandler, self).get_oem_firmware(bmcver)

    def get_oem_capping_enabled(self):
        if self.has_tsm:
            rsp = self.ipmicmd.xraw_command(netfn=0x3a, command=0x1b,
                                            data=(3,))
            # disabled
            if rsp['data'][0] == '\x00':
                return False
            # enabled
            else:
                return True

    def set_oem_capping_enabled(self, enable):
        """Set PSU based power capping

        :param enable: True for enable and False for disable
        """
        # 1 - Enable power capping(default)
        if enable:
            statecode = 1
        # 0 - Disable power capping
        else:
            statecode = 0
        if self.has_tsm:
            self.ipmicmd.xraw_command(netfn=0x3a, command=0x1a,
                                      data=(3, statecode))
            return True

    def get_oem_remote_kvm_available(self):
        if self.has_tsm:
            rsp = self.ipmicmd.raw_command(netfn=0x3a, command=0x13)
            return rsp['data'][0] == 0
        return False

    def _restart_dns(self):
        if self.has_tsm:
            self.ipmicmd.xraw_command(netfn=0x32, command=0x6c, data=(7, 0))

    def get_oem_domain_name(self):
        if self.has_tsm:
            name = ''
            for i in range(1, 5):
                rsp = self.ipmicmd.xraw_command(netfn=0x32, command=0x6b,
                                                data=(4, i))
                name += rsp['data'][:]
            return name.rstrip('\x00')

    def set_oem_domain_name(self, name):
        if self.has_tsm:
            # set the domain name length
            data = [3, 0, 0, 0, 0, len(name)]
            self.ipmicmd.xraw_command(netfn=0x32, command=0x6c, data=data)

            # set the domain name content
            name = name.ljust(256, "\x00")
            for i in range(0, 4):
                data = [4, i+1]
                offset = i*64
                data.extend([ord(x) for x in name[offset:offset+64]])
                self.ipmicmd.xraw_command(netfn=0x32, command=0x6c, data=data)

            self._restart_dns()
            return

    """ Gets a remote console launcher for a Lenovo ThinkServer.

    Returns a tuple: (content type, launcher) or None if the launcher could
    not be retrieved."""
    def _get_ts_remote_console(self, bmc, username, password):
        # We don't establish non-secure connections without checking
        # certificates
        if not self._certverify:
            return
        conn = wc.SecureHTTPConnection(bmc, 443,
                                       verifycallback=self._certverify)
        conn.connect()
        params = urllib.urlencode({
            'WEBVAR_USERNAME': username,
            'WEBVAR_PASSWORD': password
        })
        headers = {
            'Connection': 'keep-alive'
        }
        conn.request('POST', '/rpc/WEBSES/create.asp', params, headers)
        rsp = conn.getresponse()
        if rsp.status == 200:
            body = rsp.read().split('\n')
            session_line = None
            for line in body:
                if 'SESSION_COOKIE' in line:
                    session_line = line
            if session_line is None:
                return

            session_id = session_line.split('\'')[3]
            # Usually happens when maximum number of sessions is reached
            if session_id == 'Failure_Session_Creation':
                return

            headers = {
                'Connection': 'keep-alive',
                'Cookie': 'SessionCookie=' + session_id,
            }
            conn.request(
                'GET',
                '/Java/jviewer.jnlp?EXTRNIP=' + bmc + '&JNLPSTR=JViewer',
                None, headers)
            rsp = conn.getresponse()
            if rsp.status == 200:
                return rsp.getheader('Content-Type'), base64.b64encode(
                    rsp.read())
        conn.close()

    def get_graphical_console(self):
        return self._get_ts_remote_console(self.ipmicmd.bmc,
                                           self.ipmicmd.ipmi_session.userid,
                                           self.ipmicmd.ipmi_session.password)

    def add_extra_net_configuration(self, netdata):
        if self.has_tsm:
            ipv6_addr = self.ipmicmd.xraw_command(
                netfn=0x0c, command=0x02,
                data=(0x01, 0xc5, 0x00, 0x00))["data"][1:]
            if not ipv6_addr:
                return
            ipv6_prefix = ord(self.ipmicmd.xraw_command(
                netfn=0xc, command=0x02,
                data=(0x1, 0xc6, 0, 0))['data'][1])
            if hasattr(socket, 'inet_ntop'):
                ipv6str = socket.inet_ntop(socket.AF_INET6, ipv6_addr)
            else:
                # fall back to a dumber, but more universal formatter
                ipv6str = binascii.b2a_hex(ipv6_addr)
                ipv6str = ':'.join([ipv6str[x:x+4] for x in xrange(0, 32, 4)])
            netdata['ipv6_addresses'] = [
                '{0}/{1}'.format(ipv6str, ipv6_prefix)]

    @property
    def has_megarac(self):
        # if there is functionality that is the same for tsm or generic
        # megarac, then this is appropriate.  If there's a TSM specific
        # preferred, use has_tsm first
        if self._has_megarac is not None:
            return self._has_megarac
        self._has_megarac = False
        try:
            rsp = self.ipmicmd.xraw_command(netfn=0x32, command=0x7e)
            # We don't have a handy classify-only, so use get sel policy
            # rsp should have a length of one, and be either '\x00' or '\x01'
            if len(rsp['data'][:]) == 1 and rsp['data'][0] in ('\x00', '\x01'):
                self._has_megarac = True
        except pygexc.IpmiException as ie:
            if ie.ipmicode == 0:
                # if it's a generic IpmiException rather than an error code
                # from the BMC, then this is a deeper problem than just an
                # invalid command or command length or similar
                raise
        return self._has_megarac

    def set_alert_ipv6_destination(self, ip, destination, channel):
        if self.has_megarac:
            ethidx = self._megarac_eth_index
            reqdata = bytearray([channel, 193, destination, ethidx, 0])
            parsedip = socket.inet_pton(socket.AF_INET6, ip)
            reqdata.extend(parsedip)
            reqdata.extend('\x00\x00\x00\x00\x00\x00')
            self.ipmicmd.xraw_command(netfn=0xc, command=1, data=reqdata)
            return True
        return False

    def _set_short_ris_string(self, selector, value):
        data = (1, selector, 0) + struct.unpack('{0}B'.format(len(value)),
                                                value)
        self.ipmicmd.xraw_command(netfn=0x32, command=0x9f, data=data)

    def _set_ris_string(self, selector, value):
        if len(value) > 256:
            raise pygexc.UnsupportedFunctionality(
                'Value exceeds 256 characters: {0}'.format(value))
        padded = value + (256 - len(value)) * '\x00'
        padded = list(struct.unpack('256B', padded))
        # 8 = RIS, 4 = hd, 2 = fd, 1 = cd
        try:  # try and clear in-progress if left incomplete
            self.ipmicmd.xraw_command(netfn=0x32, command=0x9f,
                                      data=(1, selector, 0, 0))
        except pygexc.IpmiException:
            pass
        # set in-progress
        self.ipmicmd.xraw_command(netfn=0x32, command=0x9f,
                                  data=(1, selector, 0, 1))
        # now do the set
        for x in xrange(0, 256, 64):
            currdata = padded[x:x+64]
            currchunk = x // 64 + 1
            cmddata = [1, selector, currchunk] + currdata
            self.ipmicmd.xraw_command(netfn=0x32, command=0x9f, data=cmddata)
        # unset in-progress
        self.ipmicmd.xraw_command(netfn=0x32, command=0x9f,
                                  data=(1, selector, 0, 0))

    def _megarac_fetch_image_shortnames(self):
        rsp = self.ipmicmd.xraw_command(netfn=0x32, command=0xd8,
                                        data=(7, 1, 0))
        imgnames = rsp['data'][1:]
        shortnames = []
        for idx in xrange(0, len(imgnames), 22):
            shortnames.append(imgnames[idx+2:idx+22].rstrip('\0'))
        return shortnames

    def _megarac_media_waitforready(self, imagename):
        # first, we have, sadly, a 10 second grace period for some invisible
        # async activity to get far enough long to monitor
        self.ipmicmd.ipmi_session.pause(10)
        risenabled = '\x00'
        mountok = '\xff'
        while risenabled != '\x01':
            risenabled = self.ipmicmd.xraw_command(
                netfn=0x32, command=0x9e, data=(8, 10))['data'][2]
        while mountok == '\xff':
            mountok = self.ipmicmd.xraw_command(
                netfn=0x32, command=0x9e, data=(1, 8))['data'][2]
        targshortname = _megarac_abbrev_image(imagename)
        shortnames = self._megarac_fetch_image_shortnames()
        while targshortname not in shortnames:
            self.ipmicmd.wait_for_rsp(1)
            shortnames = self._megarac_fetch_image_shortnames()
        self.ipmicmd.ipmi_session.pause(10)
        try:
            self.ipmicmd.xraw_command(netfn=0x32, command=0xa0, data=(1, 0))
            self.ipmicmd.ipmi_session.pause(5)
        except pygexc.IpmiException:
            pass

    def _megarac_attach_media(self, proto, username, password, imagename,
                              domain, path, host):
        # First we must ensure that the RIS is actually enabled
        self.ipmicmd.xraw_command(netfn=0x32, command=0x9f, data=(8, 10, 0, 1))
        if username is not None:
            self._set_ris_string(3, username)
        if password is not None:
            self._set_short_ris_string(4, password)
        if domain is not None:
            self._set_ris_string(6, domain)
        self._set_ris_string(1, path)
        ip = util.get_ipv4(host)[0]
        self._set_short_ris_string(2, ip)
        self._set_short_ris_string(5, proto)
        # now to restart RIS to have changes take effect...
        self.ipmicmd.xraw_command(netfn=0x32, command=0x9f, data=(8, 11))
        # now to kick off the requested mount
        self._megarac_media_waitforready(imagename)
        self._set_ris_string(0, imagename)
        self.ipmicmd.xraw_command(netfn=0x32, command=0xa0,
                                  data=(1, 1))

    def attach_remote_media(self, url, username, password):
        if self.has_megarac:
            proto, host, path = util.urlsplit(url)
            if proto == 'smb':
                proto = 'cifs'
            domain = None
            path, imagename = path.rsplit('/', 1)
            if username is not None and '@' in username:
                username, domain = username.split('@', 1)
            elif username is not None and '\\' in username:
                domain, username = username.split('\\', 1)
            try:
                self._megarac_attach_media(proto, username, password,
                                           imagename, domain, path, host)
            except pygexc.IpmiException as ie:
                if ie.ipmicode in (0x92, 0x99):
                    # if starting from scratch, this can happen...
                    self._megarac_attach_media(proto, username, password,
                                               imagename, domain, path, host)
                else:
                    raise

    def detach_remote_media(self):
        if self.has_megarac:
            self.ipmicmd.xraw_command(
                netfn=0x32, command=0x9f, data=(8, 10, 0, 0))
            self.ipmicmd.xraw_command(netfn=0x32, command=0x9f, data=(8, 11))
