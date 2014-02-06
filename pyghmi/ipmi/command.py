# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
# This represents the low layer message framing portion of IPMI

import pyghmi.constants as const
import pyghmi.exceptions as exc

from pyghmi.ipmi.private import session
import pyghmi.ipmi.sdr as sdr


boot_devices = {
    'net': 4,
    'network': 4,
    'pxe': 4,
    'hd': 8,
    'cd': 0x14,
    'cdrom': 0x14,
    'dvd': 0x14,
    'floppy': 0x3c,
    'default': 0x0,
    'setup': 0x18,
    'f1': 0x18,
    1: 'network',
    2: 'hd',
    5: 'optical',
    6: 'setup',
    0: 'default'
}

power_states = {
    "off": 0,
    "on": 1,
    "reset": 3,
    "softoff": 5,
    "shutdown": 5,
    # NOTE(jbjohnso): -1 is not a valid direct boot state,
    #                 but here for convenience of 'in' statement
    "boot": -1,
}


class Command(object):
    """Send IPMI commands to BMCs.

    This object represents a persistent session to an IPMI device (bmc) and
    allows the caller to reuse a single session to issue multiple commands.
    This class can be used in a synchronous (wait for answer and return) or
    asynchronous fashion (return immediately and provide responses by
    callbacks).  Synchronous mode is the default behavior.

    For asynchronous mode, simply pass in a callback function.  It is
    recommended to pass in an instance method to callback and ignore the
    callback_args parameter. However, callback_args can optionally be populated
    if desired.

    :param bmc: hostname or ip address of the BMC
    :param userid: username to use to connect
    :param password: password to connect to the BMC
    :param onlogon: function to run when logon completes in an asynchronous
                    fashion.  This will result in a greenthread behavior.
    :param kg: Optional parameter to use if BMC has a particular Kg configured
    """

    def __init__(self, bmc, userid, password, port=623, onlogon=None, kg=None):
        # TODO(jbjohnso): accept tuples and lists of each parameter for mass
        # operations without pushing the async complexities up the stack
        self.onlogon = onlogon
        self.bmc = bmc
        if onlogon is not None:
            self.ipmi_session = session.Session(bmc=bmc,
                                                userid=userid,
                                                password=password,
                                                onlogon=self.logged,
                                                port=port,
                                                kg=kg)
            # induce one iteration of the loop, now that we would be
            # prepared for it in theory
            session.Session.wait_for_rsp(0)
        else:
            self.ipmi_session = session.Session(bmc=bmc,
                                                userid=userid,
                                                password=password,
                                                port=port,
                                                kg=kg)

    def logged(self, response):
        self.onlogon(response, self)

    @classmethod
    def eventloop(cls):
        while (session.Session.wait_for_rsp()):
            pass

    @classmethod
    def wait_for_rsp(cls, timeout):
        """Delay for no longer than timeout for next response.

        This acts like a sleep that exits on activity.

        :param timeout: Maximum number of seconds before returning
        """
        return session.Session.wait_for_rsp(timeout=timeout)

    def get_bootdev(self):
        """Get current boot device override information.

        Provides the current requested boot device.  Be aware that not all IPMI
        devices support this.  Even in BMCs that claim to, occasionally the
        BIOS or UEFI fail to honor it. This is usually only applicable to the
        next reboot.

        :returns: dict --The response will be provided in the return as a dict
        """
        response = self.raw_command(netfn=0, command=9, data=(5, 0, 0))
        # interpret response per 'get system boot options'
        if 'error' in response:
            return response
        # this should only be invoked for get system boot option complying to
        # ipmi spec and targeting the 'boot flags' parameter
        assert (response['command'] == 9 and
                response['netfn'] == 1 and
                response['data'][0] == 1 and
                (response['data'][1] & 0b1111111) == 5)
        if (response['data'][1] & 0b10000000 or
                not response['data'][2] & 0b10000000):
            return {'bootdev': 'default'}
        else:  # will consult data2 of the boot flags parameter for the data
            bootnum = (response['data'][3] & 0b111100) >> 2
            bootdev = boot_devices[bootnum]
            if (bootdev):
                return {'bootdev': bootdev}
            else:
                return {'bootdev': bootnum}

    def set_power(self, powerstate, wait=False):
        """Request power state change

        :param powerstate:
                            * on -- Request system turn on
                            * off -- Request system turn off without waiting
                                     for OS to shutdown
                            * shutdown -- Have system request OS proper
                                          shutdown
                            * reset -- Request system reset without waiting for
                              OS
                            * boot -- If system is off, then 'on', else 'reset'
        :param wait: If True, do not return until system actually completes
                     requested state change for 300 seconds.
                     If a non-zero number, adjust the wait time to the
                     requested number of seconds
        :returns: dict -- A dict describing the response retrieved
        """
        if powerstate not in power_states:
            raise exc.InvalidParameterValue(
                "Unknown power state %s requested" % powerstate)
        self.newpowerstate = powerstate
        response = self.raw_command(netfn=0, command=1)
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        if self.powerstate == self.newpowerstate:
            return {'powerstate': self.powerstate}
        if self.newpowerstate == 'boot':
            self.newpowerstate = 'on' if self.powerstate == 'off' else 'reset'
        response = self.raw_command(
            netfn=0, command=2, data=[power_states[self.newpowerstate]])
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        self.lastresponse = {'pendingpowerstate': self.newpowerstate}
        waitattempts = 300
        if not isinstance(wait, bool):
            waitattempts = wait
        if (wait and
           self.newpowerstate in ('on', 'off', 'shutdown', 'softoff')):
            if self.newpowerstate in ('softoff', 'shutdown'):
                self.waitpowerstate = 'off'
            else:
                self.waitpowerstate = self.newpowerstate
            currpowerstate = None
            while currpowerstate != self.waitpowerstate and waitattempts > 0:
                response = self.raw_command(netfn=0, command=1, delay_xmit=1)
                if 'error' in response:
                    return response
                currpowerstate = 'on' if (response['data'][0] & 1) else 'off'
                waitattempts -= 1
            if currpowerstate != self.waitpowerstate:
                raise exc.IpmiException(
                    "System did not accomplish power state change")
            return {'powerstate': currpowerstate}
        else:
            return self.lastresponse

    def set_bootdev(self,
                    bootdev,
                    persist=False,
                    uefiboot=False,
                    callback=None,
                    callback_args=None):
        """Set boot device to use on next reboot

        :param bootdev:
                        *net -- Request network boot
                        *hd -- Boot from hard drive
                        *optical -- boot from CD or DVD drive
                        *setup -- Boot into setup utility
                        *default -- remove any IPMI directed boot device
                                    request
        :param persist: If true, ask that system firmware use this device
                        beyond next boot.  Be aware many systems do not honor
                        this
        :param uefiboot: If true, request UEFI boot explicitly.  Strictly
                         speaking, the spec sugests that if not set, the system
                         should BIOS boot and offers no "don't care" option.
                         In practice, this flag not being set does not preclude
                         UEFI boot on any system I've encountered.
        :param callback: optional callback
        :param callback_args: optional arguments to callback
        :returns: dict or True -- If callback is not provided, the response
        """

        self.commandcallback = callback
        self.commandcallbackargs = callback_args
        if bootdev not in boot_devices:
            return {'error': "Unknown bootdevice %s requested" % bootdev}
        self.bootdev = boot_devices[bootdev]
        self.persistboot = persist
        self.uefiboot = uefiboot
        # first, we disable timer by way of set system boot options,
        # then move on to set chassis capabilities
        self.requestpending = True
        # Set System Boot Options is netfn=0, command=8, data
        response = self.raw_command(netfn=0, command=8, data=(3, 8))
        self.lastresponse = response
        if 'error' in response:
            return response
        bootflags = 0x80
        if self.uefiboot:
            bootflags = bootflags | 1 << 5
        if self.persistboot:
            bootflags = bootflags | 1 << 6
        if self.bootdev == 0:
            bootflags = 0
        data = (5, bootflags, self.bootdev, 0, 0, 0)
        response = self.raw_command(netfn=0, command=8, data=data)
        if 'error' in response:
            return response
        return {'bootdev': bootdev}

    def raw_command(self, netfn, command, bridge_request={}, data=()):
        """Send raw ipmi command to BMC

        This allows arbitrary IPMI bytes to be issued.  This is commonly used
        for certain vendor specific commands.

        Example: ipmicmd.raw_command(netfn=0,command=4,data=(5))

        :param netfn: Net function number
        :param command: Command value
        :param bridge_request: The target slave address and channel number for
                               the bridge request.
        :param data: Command data as a tuple or list
        :returns: dict -- The response from IPMI device
        """
        return self.ipmi_session.raw_command(netfn=netfn, command=command,
                                             bridge_request=bridge_request,
                                             data=data)

    def get_power(self):
        """Get current power state of the managed system

        The response, if successful, should contain 'powerstate' key and
        either 'on' or 'off' to indicate current state.

        :returns: dict -- {'powerstate': value}
        """
        response = self.raw_command(netfn=0, command=1)
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        assert(response['command'] == 1 and response['netfn'] == 1)
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        return {'powerstate': self.powerstate}

    def get_health(self):
        """Summarize health of managed system

        This provides a summary of the health of the managed system.
        It additionally provides an iterable list of reasons for
        warning, critical, or failed assessments.
        """
        summary = {}
        summary['badreadings'] = []
        summary['health'] = const.Health.Ok
        for reading in self.get_sensor_data():
            if reading.health != const.Health.Ok:
                summary['health'] |= reading.health
                summary['badreadings'].append(reading)
        return summary

    def get_sensor_data(self):
        """Get sensor reading objects

        Iterates sensor reading objects pertaining to the currently
        managed BMC.

        :returns: Iterator of sdr.SensorReading objects
        """
        if '_sdr' not in self.__dict__:
            self._sdr = sdr.SDR(self)
        for sensor in self._sdr.get_sensor_numbers():
            rsp = self.raw_command(command=0x2d, netfn=4, data=(sensor,))
            if 'error' in rsp:
                if rsp['code'] == 203:  # Sensor does not exist, optional dev
                    continue
                raise Exception(rsp['error'])
            yield self._sdr.sensors[sensor].decode_sensor_reading(rsp['data'])
