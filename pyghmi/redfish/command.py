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

import json
import os
import pyghmi.exceptions as exc
import pyghmi.constants as const
import pyghmi.util.webclient as webclient
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

class Command(object):

    def __init__(self, bmc, userid, password, verifycallback, sysurl=None,
                 bmcurl=None, chassisurl=None):
        self.wc = webclient.SecureHTTPConnection(
            bmc, 443, verifycallback=verifycallback)
        self._varbmcurl = bmcurl
        self._varchassisurl = chassisurl
        self._varresetbmcurl = None
        self._storedsysinfvintage = 0
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
    def sysinfo(self):
        now = os.times()[4]
        if self._storedsysinfvintage < now - 1:
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
    def _bmcurl(self):
        if not self._varbmcurl:
            self._varbmcurl = self.sysinfo.get('Links', {}).get(
                'ManagedBy', [{}])[0].get('@odata.id', None)
        return self._varbmcurl

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

    _healthmap = {
        'Critical': const.Health.Critical,
        'Warning': const.Health.Warning,
        'OK': const.Health.Ok,
    }

    def get_health(self, verbose=True):
        health = self.sysinfo.get('Status', {}).get('HealthRollup', None)
        health = self._healthmap[health]
        summary = {'badcomponents': [], 'health': health}
        if health > 0 and verbose:
            # now have to manually peruse all psus, fans, processors, ram,
            # storage
            procurl = self.sysinfo.get('Processors', {}).get('@odata.id', None)
            if procurl:
                for cpu in self._do_web_request(procurl).get('Members', []):
                    cinfo = self._do_web_request(cpu['@odata.id'])
                    if cinfo['Status']['Health'] != 'OK':
                        summary['badcomponents'].append(cinfo['Name'])
            if self.sysinfo.get('MemorySummary', {}).get('Status', {}).get(
                    'HealthRollup', 'OK') not in ('OK', None):
                dimmfound = False
                for mem in self._do_web_request(
                        self.sysinfo['Memory']['@odata.id'])['Members']:
                    dimminfo = self._do_web_request(mem)
                    if dimminfo['Status']['Health'] not in ('OK', None):
                        summary['badcomponents'].append(dimminfo['Name'])
                        dimmfound = True
                if not dimmfound:
                    summary['badcomponents'].append('Memory')
                for adapter in self.sysinfo['PCIeDevices']:
                    adpinfo = self._do_web_request(adapter['@odata.id'])
                    if adpinfo['Status']['Health'] not in ('OK', None):
                        summary['badcomponents'].append(adpinfo['Name'])
                for fun in self.sysinfo['PCIeFunctions']:
                    funinfo = self._do_web_request(fun['@odata.id'])
                    if funinfo['Status']['Health'] not in ('OK', None):
                        summary['badcomponents'].append(funinfo['Name'])
        return summary


if __name__ == '__main__':
    import os
    import sys
    print(repr(
        Command(sys.argv[1], os.environ['BMCUSER'], os.environ['BMCPASS'],
                verifycallback=lambda x: True).get_power()))
