# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2018 Lenovo
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

# The command module for redfish systems.  Provides https-only support
# for redfish compliant endpoints

from datetime import datetime
from dateutil import tz
import json
import os
import pyghmi.exceptions as exc
import pyghmi.constants as const
import pyghmi.util.webclient as webclient
import socket
import struct
import time

powerstates = {
    'on': 'On',
    'off': 'ForceOff',
    'softoff': 'GracefulShutdown',
    'shutdown': 'GracefulShutdown',
    'reset': 'ForceRestart',
    'boot': None,
}

boot_devices_write = {
    'net': 'Pxe',
    'network': 'Pxe',
    'pxe': 'Pxe',
    'hd': 'Hdd',
    'cd': 'Cd',
    'cdrom': 'Cd',
    'optical': 'Cd',
    'dvd': 'Cd',
    'floppy': 'Floppy',
    'default': 'None',
    'setup': 'BiosSetup',
    'bios': 'BiosSetup',
    'f1': 'BiosSetup',
}

boot_devices_read = {
    'BiosSetup': 'setup',
    'Cd': 'optical',
    'Floppy': 'floppy',
    'Hdd': 'hd',
    'None': 'default',
    'Pxe': 'network',
    'Usb': 'usb',
    'SDCard': 'sdcard',
}


_healthmap = {
    'Critical': const.Health.Critical,
    'Warning': const.Health.Warning,
    'OK': const.Health.Ok,
}

def _parse_time(timeval):
    if timeval is None:
        return None
    try:
        retval = datetime.strptime(timeval, '%Y-%m-%dT%H:%M:%SZ')
        return retval.replace(tzinfo=tz.tzutc())
    except ValueError:
        pass
    try:
        positive = None
        offset = None
        if '+' in timeval:
            timeval, offset = timeval.split('+', 1)
            positive = 1
        elif len(timeval.split('-')) > 3:
            timeval, offset = timeval.rsplit('-', 1)
            positive = -1
        if positive:
            hrs, mins = offset.split(':', 1)
            secs = int(hrs) * 60 + int(mins)
            secs = secs * 60 * positive
            retval = datetime.strptime(timeval, '%Y-%m-%dT%H:%M:%S')
            return retval.replace(tzinfo=tz.tzoffset('', secs))
    except ValueError:
        pass
    try:
        return datetime.strptime(timeval, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        pass
    try:
        return datetime.strptime(timeval, '%Y-%m-%d')
    except ValueError:
        pass
    return None


def _mask_to_cidr(mask):
    maskn = socket.inet_pton(socket.AF_INET, mask)
    maskn = struct.unpack('!I', maskn)[0]
    cidr = 32
    while maskn & 0b1 == 0 and cidr > 0:
        cidr -= 1
        maskn >>= 1
    return cidr


class SensorReading(object):
    def __init__(self, healthinfo):
        self.name = healthinfo['Name']
        self.health = _healthmap[healthinfo['Status']['Health']]
        self.states = [healthinfo['Status']['Health']]
        self.value = None
        self.state_ids = None
        self.imprecision = None
        self.units = None

class Command(object):

    def __init__(self, bmc, userid, password, verifycallback, sysurl=None,
                 bmcurl=None, chassisurl=None):
        self.wc = webclient.SecureHTTPConnection(
            bmc, 443, verifycallback=verifycallback)
        self._varbmcurl = bmcurl
        self._varbiosurl = None
        self._varbmcnicurl = None
        self._varsetbiosurl = None
        self._varchassisurl = chassisurl
        self._varresetbmcurl = None
        self._storedsysinfvintage = 0
        self._varupdateservice = None
        self._varfwinventory = None
        self.wc.set_basic_credentials(userid, password)
        self.wc.set_header('Content-Type', 'application/json')
        overview = self.wc.grab_json_response('/redfish/v1/')
        systems = overview['Systems']['@odata.id']
        members = self.wc.grab_json_response(systems)
        systems = members['Members']
        if sysurl:
            for system in systems:
                if system['@odata.id'] == sysurl:
                    self.sysurl = sysurl
                    break
            else:
                raise exc.PyghmiException(
                    'Specified sysurl not found: '.format(sysurl))
        else:
            if len(systems) != 1:
                raise pygexc.PyghmiException(
                    'Multi system manager, sysurl is required parameter')
            self.sysurl = systems[0]['@odata.id']
        self.powerurl = self.sysinfo.get('Actions', {}).get(
            '#ComputerSystem.Reset', {}).get('target', None)

    @property
    def _updateservice(self):
        if not self._varupdateservice:
            overview = self._do_web_request('/redfish/v1/')
            us = overview.get('UpdateService', {}).get('@odata.id', None)
            if not us:
                raise exc.UnsupportedFunctionality(
                    'BMC does not implement extended firmware information')
            self._varupdateservice = us
        return self._varupdateservice

    @property
    def _fwinventory(self):
        if not self._varfwinventory:
            usi = self._do_web_request(self._updateservice)
            self._varfwinventory = usi.get('FirmwareInventory', {}).get(
                '@odata.id', None)
            if not self._varfwinventory:
                raise exc.UnsupportedFunctionality(
                    'BMC does not implement extended firmware information')
        return self._varfwinventory





    @property
    def sysinfo(self):
        now = os.times()[4]
        if self._storedsysinfvintage < now - 2:
            self._storedsysinfvintage = now
            self._storedsysinfo = self._do_web_request(self.sysurl)
        return self._storedsysinfo


    def get_power(self):
        return {'powerstate': str(self.sysinfo['PowerState'].lower())}

    def set_power(self, powerstate, wait=False):
        if powerstate == 'boot':
            oldpowerstate = self.get_power()['powerstate']
            powerstate = 'on' if oldpowerstate == 'off' else 'reset'
        reqpowerstate = powerstate
        if powerstate not in powerstates:
            raise exc.InvalidParameterValue(
                "Unknown power state %s requested" % powerstate)
        powerstate = powerstates[powerstate]
        result = self.wc.grab_json_response_with_status(
            self.powerurl, {'ResetType': powerstate})
        if result[1] < 200 or result[1] >= 300:
            raise exc.PyghmiException(result[0])
        if wait and reqpowerstate in ('on', 'off', 'softoff', 'shutdown'):
            if reqpowerstate in ('softoff', 'shutdown'):
                reqpowerstate = 'off'
            timeout = os.times()[4] + 300
            while (self.get_power()['powerstate'] != reqpowerstate and
                   os.times()[4] < timeout):
                time.sleep(1)
            if self.get_power()['powerstate'] != reqpowerstate:
                raise exc.PyghmiException(
                    "System did not accomplish power state change")
            return {'powerstate': reqpowerstate}
        return {'pendingpowerstate': reqpowerstate}

    def _do_web_request(self, url, payload=None, method=None):
        res = self.wc.grab_json_response_with_status(url, payload,
                                                     method=method)
        if res[1] < 200 or res[1] >=300:
            raise exc.PyghmiException(res[0])
        return res[0]

    def get_bootdev(self):
        """Get current boot device override information.

        :raises: PyghmiException on error
        :returns: dict
        """
        result = self._do_web_request(self.sysurl)
        overridestate = result.get('Boot', {}).get(
            'BootSourceOverrideEnabled', None)
        if overridestate == 'Disabled':
            return {'bootdev': 'default', 'persistent': True}
        persistent = None
        if overridestate == 'Once':
            persistent = False
        elif overridestate == 'Continuous':
            persistent = True
        else:
            raise exc.PyghmiException('Unrecognized Boot state: ' +
                                      repr(overridestate))
        uefimode = result.get('Boot', {}).get('BootSourceOverrideMode', None)
        if uefimode == 'UEFI':
            uefimode = True
        elif uefimode ==  'Legacy':
            uefimode = False
        else:
            raise exc.PyghmiException('Unrecognized mode: ' + uefimode)
        bootdev = result.get('Boot', {}).get('BootSourceOverrideTarget', None)
        if bootdev not in boot_devices_read:
            raise exc.PyghmiException('Unrecognized boot target: ' +
                                      repr(bootdev))
        bootdev = boot_devices_read[bootdev]
        return {'bootdev': bootdev, 'persistent': persistent,
                'uefimode': uefimode}

    def set_bootdev(self, bootdev, persist=False, uefiboot=None):
        """Set boot device to use on next reboot

        :param bootdev:
                        *network -- Request network boot
                        *hd -- Boot from hard drive
                        *safe -- Boot from hard drive, requesting 'safe mode'
                        *optical -- boot from CD/DVD/BD drive
                        *setup -- Boot into setup utility
                        *default -- remove any directed boot device request
        :param persist: If true, ask that system firmware use this device
                        beyond next boot.  Be aware many systems do not honor
                        this
        :param uefiboot: If true, request UEFI boot explicitly.  If False,
                         request BIOS style boot.
                         None (default) does not modify the boot mode.
        :raises: PyghmiException on an error.
        :returns: dict or True -- If callback is not provided, the response
        """
        reqbootdev = bootdev
        if (bootdev not in boot_devices_write and
                bootdev not in boot_devices_read):
            raise exc.InvalidParameterValue('Unsupported device ' +
                                            repr(bootdev))
        bootdev = boot_devices_write.get(bootdev, bootdev)
        if bootdev == 'None':
            payload = {'Boot': {'BootSourceOverrideEnabled': 'Disabled'}}
        else:
            payload = {'Boot': {
                'BootSourceOverrideEnabled': 'Continuous' if persist else 'Once',
                'BootSourceOverrideTarget': bootdev,
            }}
            if uefiboot is not None:
                uefiboot = 'UEFI' if uefiboot else 'Legacy'
                payload['BootSourceOverrideMode'] = uefiboot
        self._do_web_request(self.sysurl, payload, method='PATCH')
        return {'bootdev': reqbootdev}

    @property
    def _biosurl(self):
        if not self._varbiosurl:
            self._varbiosurl = self.sysinfo.get('Bios', {}).get('@odata.id',
                                                              None)
        if self._varbiosurl is None:
            raise exc.UnsupportedFunctionality(
                'Bios management not detected on this platform')
        return self._varbiosurl

    @property
    def _setbiosurl(self):
        if self._varsetbiosurl is None:
            biosinfo = self._do_web_request(self._biosurl)
            self._varsetbiosurl = biosinfo.get(
                '@Redfish.Settings', {}).get('SettingsObject', {}).get(
                '@odata.id', None)
        if self._varsetbiosurl is None:
            raise exc.UnsupportedFunctionality('Ability to set BIOS settings '
                                               'not detected on this platform')
        return self._varsetbiosurl

    @property
    def _bmcurl(self):
        if not self._varbmcurl:
            self._varbmcurl = self.sysinfo.get('Links', {}).get(
                'ManagedBy', [{}])[0].get('@odata.id', None)
        return self._varbmcurl

    @property
    def _bmcnicurl(self):
        if not self._varbmcnicurl:
            bmcinfo = self._do_web_request(self._bmcurl)
            nicurl = bmcinfo.get('EthernetInterfaces', {}).get('@odata.id',
                                                               None)
            niclist = self._do_web_request(nicurl)
            foundnics = 0
            lastnicurl = None
            for nic in niclist.get('Members', []):
                curl = nic.get('@odata.id', None)
                if not curl:
                    continue
                nicinfo = self._do_web_request(curl)
                if nicinfo.get('Links', {}).get('HostInterface', None):
                    # skip host interface
                    continue
                foundnics += 1
                lastnicurl = curl
            if foundnics != 1:
                raise exc.PyghmiException(
                    'BMC does not have exactly one interface')
            self._varbmcnicurl = lastnicurl
        return self._varbmcnicurl


    @property
    def _bmcreseturl(self):
        if not self._varresetbmcurl:
            bmcinfo = self._do_web_request(self._bmcurl)
            self._varresetbmcurl = bmcinfo.get('Actions', {}).get(
                '#Manager.Reset', {}).get('target', None)
        return self._varresetbmcurl

    def reset_bmc(self):
        self._do_web_request(self._bmcreseturl,
                             {'ResetType': 'ForceRestart'})

    def set_identify(self, on=True, blink=None):
        self._do_web_request(
            self.sysurl,
            {'IndicatorLED': 'Blinking' if blink else 'Lit' if on else 'Off'},
            method='PATCH')

    _idstatemap = {
        'Blinking': 'blink',
        'Lit': 'on',
        'Off': 'off',
    }

    def get_identify(self):
        ledstate = self.sysinfo['IndicatorLED']
        return {'identifystate': self._idstatemap[ledstate]}

    def get_health(self, verbose=True):
        health = self.sysinfo.get('Status', {}).get('HealthRollup', None)
        health = _healthmap[health]
        summary = {'badreadings': [], 'health': health}
        if health > 0 and verbose:
            # now have to manually peruse all psus, fans, processors, ram,
            # storage
            procurl = self.sysinfo.get('Processors', {}).get('@odata.id', None)
            if procurl:
                for cpu in self._do_web_request(procurl).get('Members', []):
                    cinfo = self._do_web_request(cpu['@odata.id'])
                    if cinfo['Status']['Health'] != 'OK':
                        summary['badreadings'].append(SensorReading(cinfo))
            if self.sysinfo.get('MemorySummary', {}).get('Status', {}).get(
                    'HealthRollup', 'OK') not in ('OK', None):
                dimmfound = False
                for mem in self._do_web_request(
                        self.sysinfo['Memory']['@odata.id'])['Members']:
                    dimminfo = self._do_web_request(mem)
                    if dimminfo['Status']['Health'] not in ('OK', None):
                        summary['badreadings'].append(SensorReading(dimminfo))
                        dimmfound = True
                if not dimmfound:
                    meminfo = self.sysinfo['MemorySummary']
                    meminfo['Name'] = 'Memory'
                    summary['badreadings'].append(SensorReading(meminfo))
                for adapter in self.sysinfo['PCIeDevices']:
                    adpinfo = self._do_web_request(adapter['@odata.id'])
                    if adpinfo['Status']['Health'] not in ('OK', None):
                        summary['badreadings'].append(SensorReading(adpinfo))
                for fun in self.sysinfo['PCIeFunctions']:
                    funinfo = self._do_web_request(fun['@odata.id'])
                    if funinfo['Status']['Health'] not in ('OK', None):
                        summary['badreadings'].append(SensorReading(funinfo))
        return summary

    def get_system_configuration(self, hideadvanced=True):
        biosinfo = self._do_web_request(self._biosurl)
        currsettings = {}
        for setting in biosinfo.get('Attributes', {}):
            currsettings[setting] = {'value': biosinfo['Attributes'][setting]}
        return currsettings

    def set_system_configuration(self, changeset):
        redfishsettings = {'Attributes': changeset}
        self._do_web_request(self._setbiosurl, redfishsettings, 'PATCH')

    def get_net_configuration(self):
        netcfg = self._do_web_request(self._bmcnicurl)
        ipv4 = netcfg.get('IPv4Addresses', {})
        if not ipv4:
            raise exc.PyghmiException('Unable to locate network information')
        retval = {}
        if len(netcfg['IPv4Addresses']) != 1:
            raise exc.PyghmiException('Multiple IP addresses not supported')
        currip = netcfg['IPv4Addresses'][0]
        cidr = _mask_to_cidr(currip['SubnetMask'])
        retval['ipv4_address'] = '{0}/{1}'.format(currip['Address'], cidr)
        retval['mac_address'] = netcfg['MACAddress']
        hasgateway = _mask_to_cidr(currip['Gateway'])
        retval['ipv4_gateway'] = currip['Gateway'] if hasgateway else None
        retval['ipv4_configuration'] = currip['AddressOrigin']
        return retval

    def get_hostname(self):
        netcfg = self._do_web_request(self._bmcnicurl)
        return netcfg['HostName']

    def get_firmware(self, components=()):
        fwlist = self._do_web_request(self._fwinventory)
        for fwurl in [x['@odata.id'] for x in fwlist.get('Members', [])]:
            fwi = self._do_web_request(fwurl)
            currinf = {}
            fwname = fwi.get('Name', 'Unknown')
            currinf['version'] = fwi.get('Version', 'Unknown')
            currinf['date'] = _parse_time(fwi.get('ReleaseDate', ''))
            if not (currinf['version'] or currinf['date']):
                continue
            #TODO: OEM extended data with buildid
            currstate = fwi.get('Status', {}).get('State', 'Unknown')
            if currstate == 'StandbyOffline':
                currinf['state'] = 'pending'
            elif currstate == 'Enabled':
                currinf['state'] = 'active'
            elif currstate == 'StandbySpare':
                currinf['state'] = 'backup'
            yield fwname, currinf

    def get_inventory(self):
        sysinfo = {
            'UUID': self.sysinfo.get('UUID', ''),
            'Serial Number': self.sysinfo.get('SerialNumber', ''),
            'Manufacturer': self.sysinfo.get('Manufacturer', ''),
            'Product Name': self.sysinfo.get('Model', ''),
            'Model': self.sysinfo.get(
                'SKU', self.sysinfo.get('PartNumber', '')),
        }
        yield ('System', sysinfo)
        for cpu in self._get_cpu_inventory():
            yield cpu
        for mem in self._get_mem_inventory():
            yield mem
        for adp in self._get_adp_inventory():
            yield adp

    def _get_adp_inventory(self):
        adpurls = self.sysinfo.get('PCIeDevices', [])
        if not adpurls:
            return
        for adpurl in adpurls:
            adpinfo = self._do_web_request(adpurl['@odata.id'])
            aname = adpinfo.get('Name', 'Unknown')
            functions = adpinfo.get('Links', {}).get('PCIeFunctions', [])
            nicidx = 1
            yieldinf = {}
            for fun in functions:
                funinfo = self._do_web_request(fun['@odata.id'])
                yieldinf['PCI Device ID'] = funinfo['DeviceId'].replace('0x',
                                                                        '')
                yieldinf['PCI Vendor ID'] = funinfo['VendorId'].replace('0x',
                                                                        '')
                yieldinf['PCI Subsystem Device ID'] = funinfo[
                    'SubsystemId'].replace('0x', '')
                yieldinf['PCI Subsystem Vendor ID'] = funinfo[
                    'SubsystemVendorId'].replace('0x', '')
                yieldinf['Type'] = funinfo['DeviceClass']
                for nicinfo in funinfo.get('Links', {}).get(
                        'EthernetInterfaces', []):
                    nicinfo = self._do_web_request(nicinfo['@odata.id'])
                    macaddr = nicinfo.get('MACAddress', None)
                    if macaddr:
                        yieldinf['MAC Address {0}'.format(nicidx)] = macaddr
                        nicidx += 1
            yield aname, yieldinf

    def _get_cpu_inventory(self):
        cpurl = self.sysinfo.get('Processors', {}).get('@odata.id', None)
        if cpurl is None:
            return
        cpurl = self._do_web_request(cpurl)
        for cpu in cpurl.get('Members', []):
            currcpuinfo = self._do_web_request(cpu['@odata.id'])
            name = currcpuinfo.get('Name', 'CPU')
            cpuinfo = {'Model': currcpuinfo.get('Model', None)}
            yield (name, cpuinfo)

    def _get_mem_inventory(self):
        memurl = self.sysinfo.get('Memory', {}).get('@odata.id', None)
        if not memurl:
            return
        memurl = self._do_web_request(memurl)
        for mem in memurl.get('Members', []):
            currmeminfo = self._do_web_request(mem['@odata.id'])
            name = currmeminfo.get('Name', 'Memory')
            if currmeminfo.get(
                    'Status', {}).get('State', 'Absent') == 'Absent':
                yield (name, None)
                continue
            currspeed = currmeminfo.get('OperatingSpeedMhz', None)
            if currspeed:
                currspeed = int(currspeed)
                currspeed = currspeed * 8 - (currspeed * 8 % 100)
            meminfo = {
                'capacity_mb': currmeminfo.get('CapacityMiB', None),
                'manufacturer': currmeminfo.get('Manufacturer', None),
                'memory_type': currmeminfo.get('MemoryDeviceType', None),
                'model': currmeminfo.get('PartNumber', None),
                'module_type': currmeminfo.get('BaseModuleType', None),
                'serial': currmeminfo.get('SerialNumber', None),
                'speed': currspeed,
            }
            yield (name, meminfo)


if __name__ == '__main__':
    import os
    import sys
    print(repr(
        Command(sys.argv[1], os.environ['BMCUSER'], os.environ['BMCPASS'],
                verifycallback=lambda x: True).get_power()))
