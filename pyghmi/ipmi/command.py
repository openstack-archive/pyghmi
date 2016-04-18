# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 IBM Corporation
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
# This represents the low layer message framing portion of IPMI

from itertools import chain
import pyghmi.constants as const
import pyghmi.exceptions as exc

import pyghmi.ipmi.events as sel
import pyghmi.ipmi.fru as fru
from pyghmi.ipmi.oem.lookup import get_oem_handler
from pyghmi.ipmi.private import session
import pyghmi.ipmi.private.util as pygutil
import pyghmi.ipmi.sdr as sdr
import socket
import struct


boot_devices = {
    'net': 4,
    'network': 4,
    'pxe': 4,
    'hd': 8,
    'safe': 0xc,
    'cd': 0x14,
    'cdrom': 0x14,
    'optical': 0x14,
    'dvd': 0x14,
    'floppy': 0x3c,
    'default': 0x0,
    'setup': 0x18,
    'bios': 0x18,
    'f1': 0x18,
    1: 'network',
    2: 'hd',
    3: 'safe',
    5: 'optical',
    6: 'setup',
    15: 'floppy',
    0: 'default'
}

power_states = {
    "off": 0,
    "on": 1,
    "reset": 3,
    "diag": 4,
    "softoff": 5,
    "shutdown": 5,
    # NOTE(jbjohnso): -1 is not a valid direct boot state,
    #                 but here for convenience of 'in' statement
    "boot": -1,
}


def _mask_to_cidr(mask):
    maskn = struct.unpack_from('>I', mask)[0]
    cidr = 32
    while maskn & 0b1 == 0 and cidr > 0:
        cidr -= 1
        maskn >>= 1
    return cidr


def _cidr_to_mask(prefix):
    return struct.pack('>I', 2**prefix-1 << (32-prefix))


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
        self._sdr = None
        self._oem = None
        self._netchannel = None
        self._ipv6support = None
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

    def register_key_handler(self, callback, type='tls'):
        """Assign a verification handler for a public key

        When the library attempts to communicate with the management target
        using a non-IPMI protocol, it will try to verify a key.  This
        allows a caller to register a key handler for accepting or rejecting
        a public key/certificate.  The callback will be passed the peer public
        key or certificate.

        :param callback:  The function to call with public key/certificate
        :param type: Whether the callback is meant to handle 'tls' or 'ssh',
                     defaults to 'tls'
        """
        if type == 'tls':
            self._certverify = callback
        self.oem_init()
        self._oem.register_key_handler(callback, type)

    def logged(self, response):
        self.onlogon(response, self)
        self.onlogon = None

    @classmethod
    def eventloop(cls):
        while session.Session.wait_for_rsp():
            pass

    @classmethod
    def wait_for_rsp(cls, timeout):
        """Delay for no longer than timeout for next response.

        This acts like a sleep that exits on activity.

        :param timeout: Maximum number of seconds before returning
        """
        return session.Session.wait_for_rsp(timeout=timeout)

    def _get_device_id(self):
        response = self.raw_command(netfn=0x06, command=0x01)
        if 'error' in response:
            raise exc.IpmiException(response['error'], code=response['code'])
        return {
            'device_id': response['data'][0],
            'device_revision': response['data'][1] & 0b1111,
            'manufacturer_id': struct.unpack(
                '<I', struct.pack('3B', *response['data'][6:9]) + '\x00')[0],
            'product_id': struct.unpack(
                '<H', struct.pack('2B', *response['data'][9:11]))[0],
        }

    def oem_init(self):
        """Initialize the command object for OEM capabilities

        A number of capabilities are either totally OEM defined or
        else augmented somehow by knowledge of the OEM.  This
        method does an interrogation to identify the OEM.

        """
        if self._oem:
            return
        self._oem = get_oem_handler(self._get_device_id(), self)

    def get_bootdev(self):
        """Get current boot device override information.

        Provides the current requested boot device.  Be aware that not all IPMI
        devices support this.  Even in BMCs that claim to, occasionally the
        BIOS or UEFI fail to honor it. This is usually only applicable to the
        next reboot.

        :raises: IpmiException on an error.
        :returns: dict --The response will be provided in the return as a dict
        """
        response = self.raw_command(netfn=0, command=9, data=(5, 0, 0))
        # interpret response per 'get system boot options'
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        # this should only be invoked for get system boot option complying to
        # ipmi spec and targeting the 'boot flags' parameter
        assert (response['command'] == 9 and
                response['netfn'] == 1 and
                response['data'][0] == 1 and
                (response['data'][1] & 0b1111111) == 5)
        if (response['data'][1] & 0b10000000 or
                not response['data'][2] & 0b10000000):
            return {'bootdev': 'default', 'persistent': True}
        else:  # will consult data2 of the boot flags parameter for the data
            persistent = False
            uefimode = False
            if response['data'][2] & 0b1000000:
                persistent = True
            if response['data'][2] & 0b100000:
                uefimode = True
            bootnum = (response['data'][3] & 0b111100) >> 2
            bootdev = boot_devices.get(bootnum)
            if bootdev:
                return {'bootdev': bootdev,
                        'persistent': persistent,
                        'uefimode': uefimode}
            else:
                return {'bootdev': bootnum,
                        'persistent': persistent,
                        'uefimode': uefimode}

    def set_power(self, powerstate, wait=False):
        """Request power state change (helper)

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
        newpowerstate = powerstate
        response = self.raw_command(netfn=0, command=1)
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        oldpowerstate = 'on' if (response['data'][0] & 1) else 'off'
        if oldpowerstate == newpowerstate:
            return {'powerstate': oldpowerstate}
        if newpowerstate == 'boot':
            newpowerstate = 'on' if oldpowerstate == 'off' else 'reset'
        response = self.raw_command(
            netfn=0, command=2, data=[power_states[newpowerstate]])
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        lastresponse = {'pendingpowerstate': newpowerstate}
        waitattempts = 300
        if not isinstance(wait, bool):
            waitattempts = wait
        if (wait and
           newpowerstate in ('on', 'off', 'shutdown', 'softoff')):
            if newpowerstate in ('softoff', 'shutdown'):
                waitpowerstate = 'off'
            else:
                waitpowerstate = newpowerstate
            currpowerstate = None
            while currpowerstate != waitpowerstate and waitattempts > 0:
                response = self.raw_command(netfn=0, command=1, delay_xmit=1)
                if 'error' in response:
                    return response
                currpowerstate = 'on' if (response['data'][0] & 1) else 'off'
                waitattempts -= 1
            if currpowerstate != waitpowerstate:
                raise exc.IpmiException(
                    "System did not accomplish power state change")
            return {'powerstate': currpowerstate}
        else:
            return lastresponse

    def get_video_launchdata(self):
        """Get data required to launch a remote video session to target.

        This is a highly proprietary scenario, the return data may vary greatly
        host to host.  The return should be a dict describing the type of data
        and the data.  For example {'jnlp': jnlpstring}
        """
        self.oem_init()
        return self._oem.get_video_launchdata()

    def reset_bmc(self):
        """Do a cold reset in BMC
        """
        response = self.raw_command(netfn=6, command=2)
        if 'error' in response:
            raise exc.IpmiException(response['error'])

    def set_bootdev(self,
                    bootdev,
                    persist=False,
                    uefiboot=False):
        """Set boot device to use on next reboot (helper)

        :param bootdev:
                        *network -- Request network boot
                        *hd -- Boot from hard drive
                        *safe -- Boot from hard drive, requesting 'safe mode'
                        *optical -- boot from CD/DVD/BD drive
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
        :raises: IpmiException on an error.
        :returns: dict or True -- If callback is not provided, the response
        """
        if bootdev not in boot_devices:
            return {'error': "Unknown bootdevice %s requested" % bootdev}
        bootdevnum = boot_devices[bootdev]
        # first, we disable timer by way of set system boot options,
        # then move on to set chassis capabilities
        # Set System Boot Options is netfn=0, command=8, data
        response = self.raw_command(netfn=0, command=8, data=(3, 8))
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        bootflags = 0x80
        if uefiboot:
            bootflags |= 1 << 5
        if persist:
            bootflags |= 1 << 6
        if bootdevnum == 0:
            bootflags = 0
        data = (5, bootflags, bootdevnum, 0, 0, 0)
        response = self.raw_command(netfn=0, command=8, data=data)
        if 'error' in response:
            raise exc.IpmiException(response['error'])
        return {'bootdev': bootdev}

    def xraw_command(self, netfn, command, bridge_request=(), data=(),
                     delay_xmit=None, retry=True, timeout=None):
        """Send raw ipmi command to BMC, raising exception on error

        This is identical to raw_command, except it raises exceptions
        on IPMI errors and returns data as a buffer.  This is the recommend
        function to use.  The response['data'] being a buffer allows
        traditional indexed access as well as works nicely with
        struct.unpack_from when certain data is coming back.

        :param netfn: Net function number
        :param command: Command value
        :param bridge_request: The target slave address and channel number for
                               the bridge request.
        :param data: Command data as a tuple or list
        :param retry: Whether to retry this particular payload or not, defaults
                      to true.
        :param timeout: A custom time to wait for initial reply, useful for
                        a slow command.  This may interfere with retry logic.
        :returns: dict -- The response from IPMI device
        """
        rsp = self.ipmi_session.raw_command(netfn=netfn, command=command,
                                            bridge_request=bridge_request,
                                            data=data, delay_xmit=delay_xmit,
                                            retry=retry, timeout=timeout)
        if 'error' in rsp:
            raise exc.IpmiException(rsp['error'], rsp['code'])
        rsp['data'] = buffer(bytearray(rsp['data']))
        return rsp

    def raw_command(self, netfn, command, bridge_request=(), data=(),
                    delay_xmit=None, retry=True, timeout=None):
        """Send raw ipmi command to BMC

        This allows arbitrary IPMI bytes to be issued.  This is commonly used
        for certain vendor specific commands.

        Example: ipmicmd.raw_command(netfn=0,command=4,data=(5))

        :param netfn: Net function number
        :param command: Command value
        :param bridge_request: The target slave address and channel number for
                               the bridge request.
        :param data: Command data as a tuple or list
        :param retry: Whether or not to retry command if no response received.
                      Defaults to True
        :param timeout: A custom amount of time to wait for initial reply
        :returns: dict -- The response from IPMI device
        """
        return self.ipmi_session.raw_command(netfn=netfn, command=command,
                                             bridge_request=bridge_request,
                                             data=data, delay_xmit=delay_xmit,
                                             retry=retry, timeout=timeout)

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
        powerstate = 'on' if (response['data'][0] & 1) else 'off'
        return {'powerstate': powerstate}

    def set_identify(self, on=True, duration=None):
        """Request identify light

        Request the identify light to turn off, on for a duration,
        or on indefinitely.  Other than error exceptions,

        :param on: Set to True to force on or False to force off
        :param duration: Set if wanting to request turn on for a duration
                         rather than indefinitely on
        """
        if duration is not None:
            duration = int(duration)
            if duration > 255:
                duration = 255
            if duration < 0:
                duration = 0
            response = self.raw_command(netfn=0, command=4, data=[duration])
            if 'error' in response:
                raise exc.IpmiException(response['error'])
            return
        forceon = 0
        if on:
            forceon = 1
        if self.ipmi_session.ipmiversion < 2.0:
            # ipmi 1.5 made due with just one byte, make best effort
            # to imitate indefinite as close as possible
            identifydata = [255 * forceon]
        else:
            identifydata = [0, forceon]
        response = self.raw_command(netfn=0, command=4, data=identifydata)
        if 'error' in response:
            raise exc.IpmiException(response['error'])

    def init_sdr(self):
        """Initialize SDR

        Do the appropriate action to have a relevant sensor description
        repository for the current management controller
        """
        # For now, return current sdr if it exists and still connected
        # future, check SDR timestamp for continued relevance
        # further future, optionally support a cache directory/file
        # to store cached copies for given device id, product id, mfg id,
        # sdr timestamp, our data version revision, aux firmware revision,
        # and oem defined field
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        return self._sdr

    def get_event_log(self, clear=False):
        """Retrieve the log of events, optionally clearing

        The contents of the SEL are returned as an iterable.  Timestamps
        are given as local time, ISO 8601 (whether the target has an accurate
        clock or not).  Timestamps may be omitted for events that cannot be
        given a timestamp, leaving only the raw timecode to provide relative
        time information.  clear set to true will result in the log being
        cleared as it is returned.  This allows an atomic fetch and clear
        behavior so that no log entries will be lost between the fetch and
        clear actions.  There is no 'clear_event_log' function to encourage
        users to create code that is not at risk for losing events.

        :param clear:  Whether to remove the SEL entries from the target BMC
        """
        self.oem_init()
        return sel.EventHandler(self.init_sdr(), self).fetch_sel(self, clear)

    def decode_pet(self, specifictrap, petdata):
        """Decode PET to an event

        In IPMI, the alert format are PET alerts.  It is a particular set of
        data put into an SNMPv1 trap and sent. It bears no small resemblence
        to the SEL entries.  This function takes data that would have been
        received by an SNMP trap handler, and provides an event decode, similar
        to one entry of get_event_log.

        :param specifictrap: The specific trap, as either a bytearray or int
        :param petdata: An iterable of the octet data of varbind for
                        1.3.6.1.4.1.3183.1.1.1
        :returns: A dict event similar to one iteration of get_event_log
        """
        self.oem_init()
        return sel.EventHandler(self.init_sdr(), self).decode_pet(specifictrap,
                                                                  petdata)

    def get_inventory_descriptions(self):
        """Retrieve list of things that could be inventoried

        This permits a caller to examine the available items
        without actually causing the inventory data to be gathered.  It
        returns an iterable of string descriptions
        """
        yield "System"
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        for fruid in self._sdr.fru:
            yield self._sdr.fru[fruid].fru_name
        self.oem_init()
        for compname in self._oem.get_oem_inventory_descriptions():
            yield compname

    def get_inventory_of_component(self, component):
        """Retrieve inventory of a component

        Retrieve detailed inventory information for only the requested
        component.
        """
        self.oem_init()
        if component == 'System':
            return self._get_zero_fru()
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        for fruid in self._sdr.fru:
            if self._sdr.fru[fruid].fru_name == component:
                return self._oem.process_fru(fru.FRU(
                    ipmicmd=self, fruid=fruid, sdr=self._sdr.fru[fruid]).info)
        return self._oem.get_inventory_of_component(component)

    def _get_zero_fru(self):
        # It is expected that a manufacturer matches SMBIOS to IPMI
        # get system uuid return data.  If a manufacturer does not
        # do so, they should handle either deletion or fixup in the
        # OEM processing pass.  Code optimistically assumes that if
        # data is returned, than the vendor is properly using it.
        zerofru = fru.FRU(ipmicmd=self).info
        if zerofru is None:
            zerofru = {}
        guiddata = self.raw_command(netfn=6, command=0x37)
        if 'error' not in guiddata:
            zerofru['UUID'] = pygutil.decode_wireformat_uuid(
                guiddata['data'])
        # Add some fields returned by get device ID command to FRU 0
        # Also rename them to something more in line with FRU 0 field naming
        # standards
        device_id = self._get_device_id()
        device_id['Device ID'] = device_id.pop('device_id')
        device_id['Device Revision'] = device_id.pop('device_revision')
        device_id['Manufacturer ID'] = device_id.pop('manufacturer_id')
        device_id['Product ID'] = device_id.pop('product_id')
        zerofru.update(device_id)
        return self._oem.process_fru(zerofru)

    def get_inventory(self):
        """Retrieve inventory of system

        Retrieve inventory of the targeted system.  This frequently includes
        serial numbers, sometimes hardware addresses, sometimes memory modules
        This function will retrieve whatever the underlying platform provides
        and apply some structure.  Iterating over the return yields tuples
        of a name for the inventoried item and dictionary of descriptions
        or None for items not present.
        """
        self.oem_init()
        yield ("System", self._get_zero_fru())
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        for fruid in self._sdr.fru:
            fruinf = fru.FRU(
                ipmicmd=self, fruid=fruid, sdr=self._sdr.fru[fruid]).info
            if fruinf is not None:
                fruinf = self._oem.process_fru(fruinf)
            yield (self._sdr.fru[fruid].fru_name, fruinf)
        for componentpair in self._oem.get_oem_inventory():
            yield componentpair

    def get_leds(self):
        """Get LED status information

        This provides a detailed view of the LEDs of the managed system.
        """
        self.oem_init()
        return self._oem.get_leds()

    def get_ntp_enabled(self):
        self.oem_init()
        return self._oem.get_ntp_enabled()

    def set_ntp_enabled(self, enable):
        self.oem_init()
        return self._oem.set_ntp_enabled(enable)

    def get_ntp_servers(self):
        self.oem_init()
        return self._oem.get_ntp_servers()

    def set_ntp_server(self, server, index=0):
        self.oem_init()
        return self._oem.set_ntp_server(server, index)

    def get_health(self):
        """Summarize health of managed system

        This provides a summary of the health of the managed system.
        It additionally provides an iterable list of reasons for
        warning, critical, or failed assessments.
        """
        summary = {'badreadings': [], 'health': const.Health.Ok}
        for reading in self.get_sensor_data():
            if reading.health != const.Health.Ok:
                summary['health'] |= reading.health
                summary['badreadings'].append(reading)
        return summary

    def get_sensor_reading(self, sensorname):
        """Get a sensor reading by name

        Returns a single decoded sensor reading per the name
        passed in

        :param sensorname:  Name of the desired sensor
        :returns: sdr.SensorReading object
        """
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        for sensor in self._sdr.get_sensor_numbers():
            if self._sdr.sensors[sensor].name == sensorname:
                rsp = self.raw_command(command=0x2d, netfn=4, data=(sensor,))
                if 'error' in rsp:
                    raise exc.IpmiException(rsp['error'], rsp['code'])
                return self._sdr.sensors[sensor].decode_sensor_reading(
                    rsp['data'])
        self.oem_init()
        return self._oem.get_sensor_reading(sensorname)

    def _fetch_lancfg_param(self, channel, param, prefixlen=False):
        """Internal helper for fetching lan cfg parameters

        If the parameter revison != 0x11, bail.  Further, if 4 bytes, return
        string with ipv4.  If 6 bytes, colon delimited hex (mac address).  If
        one byte, return the int value
        """
        fetchcmd = bytearray((channel, param, 0, 0))
        fetched = self.xraw_command(0xc, 2, data=fetchcmd)
        fetchdata = fetched['data']
        if ord(fetchdata[0]) != 17:
            return None
        if len(fetchdata) == 5:  # IPv4 address
            if prefixlen:
                return _mask_to_cidr(fetchdata[1:])
            else:
                ip = socket.inet_ntop(socket.AF_INET, fetchdata[1:])
                if ip == '0.0.0.0':
                    return None
                return ip
        elif len(fetchdata) == 7:  # MAC address
            mac = '{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}'.format(
                *bytearray(fetchdata[1:]))
            if mac == '00:00:00:00:00:00':
                return None
            return mac
        elif len(fetchdata) == 2:
            return ord(fetchdata[1])
        else:
            raise Exception("Unrecognized data format " + repr(fetchdata))

    def set_net_configuration(self, ipv4_address=None, ipv4_configuration=None,
                              ipv4_gateway=None, channel=None):
        """Set network configuration data.

        Apply desired network configuration data, leaving unspecified
        parameters alone.

        :param ipv4_address:  CIDR notation for IP address and netmask
                          Example: '192.168.0.10/16'
        :param ipv4_configuration: Method to use to configure the network.
                        'DHCP' or 'Static'.
        :param ipv4_gateway: IP address of gateway to use.
        :param channel:  LAN channel to configure, defaults to autodetect
        """
        if channel is None:
            channel = self.get_network_channel()
        if ipv4_configuration is not None:
            cmddata = [channel, 4, 0]
            if ipv4_configuration.lower() == 'dhcp':
                cmddata[-1] = 2
            elif ipv4_configuration.lower() == 'static':
                cmddata[-1] = 1
            else:
                raise Exception('Unrecognized ipv4cfg parameter {0}'.format(
                    ipv4_configuration))
            self.xraw_command(netfn=0xc, command=1, data=cmddata)
        if ipv4_address is not None:
            netmask = None
            if '/' in ipv4_address:
                ipv4_address, prefix = ipv4_address.split('/')
                netmask = _cidr_to_mask(int(prefix))
            cmddata = bytearray((channel, 3)) + socket.inet_aton(ipv4_address)
            self.xraw_command(netfn=0xc, command=1, data=cmddata)
            if netmask is not None:
                cmddata = bytearray((channel, 6)) + netmask
                self.xraw_command(netfn=0xc, command=1, data=cmddata)
        if ipv4_gateway is not None:
            cmddata = bytearray((channel, 12)) + socket.inet_aton(ipv4_gateway)
            self.xraw_command(netfn=0xc, command=1, data=cmddata)

    def get_net_configuration(self, channel=None, gateway_macs=True):
        """Get network configuration data

        Retrieve network configuration from the target

        :param channel: Channel to configure, defaults to None for 'autodetect'
        :param gateway_macs: Whether to retrieve mac addresses for gateways
        :returns: A dictionary of network configuration data
        """
        if channel is None:
            channel = self.get_network_channel()
        retdata = {}
        v4addr = self._fetch_lancfg_param(channel, 3)
        if v4addr is None:
            retdata['ipv4_address'] = None
        else:
            v4masklen = self._fetch_lancfg_param(channel, 6, prefixlen=True)
            retdata['ipv4_address'] = '{0}/{1}'.format(v4addr, v4masklen)
        v4cfgmethods = {
            0: 'Unspecified',
            1: 'Static',
            2: 'DHCP',
            3: 'BIOS',
            4:  'Other',
        }
        retdata['ipv4_configuration'] = v4cfgmethods[self._fetch_lancfg_param(
            channel, 4)]
        retdata['mac_address'] = self._fetch_lancfg_param(channel, 5)
        retdata['ipv4_gateway'] = self._fetch_lancfg_param(channel, 12)
        retdata['ipv4_backup_gateway'] = self._fetch_lancfg_param(channel, 14)
        if gateway_macs:
            retdata['ipv4_gateway_mac'] = self._fetch_lancfg_param(channel, 13)
            retdata['ipv4_backup_gateway_mac'] = self._fetch_lancfg_param(
                channel, 15)
        self.oem_init()
        self._oem.add_extra_net_configuration(retdata)
        return retdata

    def get_sensor_data(self):
        """Get sensor reading objects

        Iterates sensor reading objects pertaining to the currently
        managed BMC.

        :returns: Iterator of sdr.SensorReading objects
        """
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        for sensor in self._sdr.get_sensor_numbers():
            rsp = self.raw_command(command=0x2d, netfn=4, data=(sensor,))
            if 'error' in rsp:
                if rsp['code'] == 203:  # Sensor does not exist, optional dev
                    continue
                raise exc.IpmiException(rsp['error'], code=rsp['code'])
            yield self._sdr.sensors[sensor].decode_sensor_reading(rsp['data'])
        self.oem_init()
        for reading in self._oem.get_sensor_data():
            yield reading

    def get_sensor_descriptions(self):
        """Get available sensor names

        Iterates over the available sensor descriptions

        :returns: Iterator of dicts describing each sensor
        """
        if self._sdr is None:
            self._sdr = sdr.SDR(self)
        for sensor in self._sdr.get_sensor_numbers():
            yield {'name': self._sdr.sensors[sensor].name,
                   'type': self._sdr.sensors[sensor].sensor_type}
        self.oem_init()
        for sensor in self._oem.get_sensor_descriptions():
            yield sensor

    def get_network_channel(self):
        """Get a reasonable 'default' network channel.

        When configuring/examining network configuration, it's desirable to
        find the correct channel.  Here we run with the 'real' number of the
        current channel if it is a LAN channel, otherwise it evaluates
        all of the channels to find the first workable LAN channel and returns
        that
        """
        if self._netchannel is None:
            for channel in chain((0xe, ), xrange(1, 0xc)):
                try:
                    rsp = self.xraw_command(
                        netfn=6, command=0x42, data=(channel,))
                except exc.IpmiException as ie:
                    if ie.ipmicode == 0xcc:
                        # We have hit an invalid channel, move on to next
                        # candidate
                        continue
                    else:
                        raise
                chantype = ord(rsp['data'][1]) & 0b1111111
                if chantype in (4, 6):
                    try:
                        # Some implementations denote an inactive channel
                        # by refusing to do parameter retrieval
                        self.xraw_command(
                            netfn=0xc, command=2, data=(channel, 5, 0, 0))
                        # If still here, the channel seems serviceable...
                        # However some implementations may still have
                        # ambiguous channel info, that will need to be
                        # picked up on an OEM extension...
                        self._netchannel = ord(rsp['data'][0]) & 0b1111
                        break
                    except exc.IpmiException as ie:
                        # This means the attempt to fetch parameter 5 failed,
                        # therefore move on to next candidate channel
                        continue
        return self._netchannel

    def get_alert_destination_count(self, channel=None):
        """Get the number of supported alert destinations

        :param channel: Channel for alerts to be examined, defaults to current
        """
        if channel is None:
            channel = self.get_network_channel()
        rqdata = (channel, 0x11, 0, 0)
        rsp = self.xraw_command(netfn=0xc, command=2, data=rqdata)
        return ord(rsp['data'][1])

    def get_alert_destination(self, destination=0, channel=None):
        """Get alert destination

        Get a specified alert destination.  Returns a dictionary of relevant
        configuration.  The following keys may be present:
        acknowledge_required - Indicates whether the target expects an
                               acknowledgement
        acknowledge_timeout - How long it will wait for an acknowledgment
                                  before retrying
        retries - How many attempts will be made to deliver the alert to this
                  destination
        address_format - 'ipv4' or 'ipv6'
        address - The IP address of the target

        :param destination:  The destination number.  Defaults to 0
        :param channel: The channel for alerting.  Defaults to current channel
        """
        destinfo = {}
        if channel is None:
            channel = self.get_network_channel()
        rqdata = (channel, 18, destination, 0)
        rsp = self.xraw_command(netfn=0xc, command=2, data=rqdata)
        dtype, acktimeout, retries = struct.unpack('BBB', rsp['data'][2:])
        destinfo['acknowledge_required'] = dtype & 0b10000000 == 0b10000000
        # Ignore destination type for now...
        if destinfo['acknowledge_required']:
            destinfo['acknowledge_timeout'] = acktimeout
        destinfo['retries'] = retries
        rqdata = (channel, 19, destination, 0)
        rsp = self.xraw_command(netfn=0xc, command=2, data=rqdata)
        if ord(rsp['data'][2]) & 0b11110000 == 0:
            destinfo['address_format'] = 'ipv4'
            destinfo['address'] = socket.inet_ntop(socket.AF_INET,
                                                   rsp['data'][4:8])
        elif ord(rsp['data'][2]) & 0b11110000 == 0b10000:
            destinfo['address_format'] = 'ipv6'
            destinfo['address'] = socket.inet_ntop(socket.AF_INET6,
                                                   rsp['data'][3:])
        return destinfo

    def clear_alert_destination(self, destination=0, channel=None):
        """Clear an alert destination

        Remove the specified alert destination configuration.

        :param destination:  The destination to clear (defaults to 0)
        """
        if channel is None:
            channel = self.get_network_channel()
        self.set_alert_destination(
            '0.0.0.0', False, 0, 0, destination, channel)

    def set_alert_community(self, community, channel=None):
        """Set the community string for alerts

        This configures the string the BMC will use as the community string
        for PET alerts/traps.

        :param community: The community string
        :param channel: The LAN channel (defaults to auto detect)
        """
        if channel is None:
            channel = self.get_network_channel()
        community = community.encode('utf-8')
        community += b'\x00' * (18 - len(community))
        cmddata = bytearray((channel, 16))
        cmddata += community
        self.xraw_command(netfn=0xc, command=1, data=cmddata)

    def _assure_alert_policy(self, channel, destination):
        """Make sure an alert policy exists

        Each policy will be a dict with the following keys:
        -'index' - The policy index number
        :returns: An iterable of currently configured alert policies
        """
        # First we do a get PEF configuration parameters to get the count
        # of entries.  We have no guarantee that the meaningful data will
        # be contiguous
        rsp = self.xraw_command(netfn=4, command=0x13, data=(8, 0, 0))
        numpol = ord(rsp['data'][1])
        desiredchandest = (channel << 4) | destination
        availpolnum = None
        for polnum in xrange(1, numpol + 1):
            currpol = self.xraw_command(netfn=4, command=0x13,
                                        data=(9, polnum, 0))
            polidx, chandest = struct.unpack_from('>BB', currpol['data'][2:4])
            if not polidx & 0b1000:
                if availpolnum is None:
                    availpolnum = polnum
                continue
            if chandest == desiredchandest:
                return True
        # If chandest did not equal desiredchandest ever, we need to use a slot
        if availpolnum is None:
            raise Exception("No available alert policy entry")
        # 24 = 1 << 4 | 8
        # 1 == set to which this rule belongs
        # 8 == 0b1000, in other words, enable this policy, always send to
        # indicated destination
        self.xraw_command(netfn=4, command=0x12,
                          data=(9, availpolnum, 24,
                                desiredchandest, 0))

    def get_alert_community(self, channel=None):
        """Get the current community string for alerts

        Returns the community string that will be in SNMP traps from this
        BMC

        :param channel: The channel to get configuration for, autodetect by
                        default
        :returns: The community string
        """
        if channel is None:
            channel = self.get_network_channel()
        rsp = self.xraw_command(netfn=0xc, command=2, data=(channel, 16, 0, 0))
        return rsp['data'][1:].partition('\x00')[0]

    @property
    def _supports_standard_ipv6(self):
        # Supports the *standard* ipv6 commands for various things
        # used to internally steer some commands to standard or OEM
        # handler of commands
        lanchan = self.get_network_channel()
        if self._ipv6support is None:
            rsp = self.raw_command(netfn=0xc, command=0x2, data=(2, lanchan,
                                                                 0x32, 0, 0))
            self._ipv6support = rsp['code'] == 0
        return self._ipv6support

    def set_alert_destination(self, ip=None, acknowledge_required=None,
                              acknowledge_timeout=None, retries=None,
                              destination=0, channel=None):
        """Configure one or more parameters of an alert destination

        If any parameter is 'None' (default), that parameter is left unchanged.
        Otherwise, all given parameters are set by this command.

        :param ip: IP address of the destination.  It is currently expected
                   that the calling code will handle any name lookup and
                   present this data as IP address.
        :param acknowledge_required: Whether or not the target should expect
                                     an acknowledgement from this alert target.
        :param acknowledge_timeout: Time to wait for acknowledgement if enabled
        :param retries:  How many times to attempt transmit of an alert.
        :param destination:  Destination index, defaults to 0.
        :param channel: The channel to configure the alert on.  Defaults to
                current
        """
        if channel is None:
            channel = self.get_network_channel()
        if ip is not None:
            destdata = bytearray((channel, 19, destination))
            try:
                parsedip = socket.inet_pton(socket.AF_INET, ip)
                destdata.extend((0, 0))
                destdata.extend(parsedip)
                destdata.extend('\x00\x00\x00\x00\x00\x00')
            except socket.error:
                if self._supports_standard_ipv6:
                    parsedip = socket.inet_pton(socket.AF_INET6, ip)
                    destdata.append(0b10000000)
                    destdata.extend(parsedip)
                else:
                    destdata = None
                    self.oem_init()
                    self._oem.set_alert_ipv6_destination(ip, destination,
                                                         channel)
            if destdata:
                self.xraw_command(netfn=0xc, command=1, data=destdata)
        if (acknowledge_required is not None or retries is not None or
                acknowledge_timeout is not None):
            currtype = self.xraw_command(netfn=0xc, command=2, data=(
                channel, 18, destination, 0))
            if currtype['data'][0] != '\x11':
                raise exc.PyghmiException("Unknown parameter format")
            currtype = bytearray(currtype['data'][1:])
            if acknowledge_required is not None:
                if acknowledge_required:
                    currtype[1] |= 0b10000000
                else:
                    currtype[1] &= 0b1111111
            if acknowledge_timeout is not None:
                currtype[2] = acknowledge_timeout
            if retries is not None:
                currtype[3] = retries
            destreq = bytearray((channel, 18))
            destreq.extend(currtype)
            self.xraw_command(netfn=0xc, command=1, data=destreq)
        if not ip == '0.0.0.0':
            self._assure_alert_policy(channel, destination)

    def get_mci(self):
        """Get the Management Controller Identifier, per DCMI specification

        :returns: The identifier as a string
        """
        return self._chunkwise_dcmi_fetch(9)

    def set_mci(self, mci):
        """Set the management controller identifier, per DCMI specification

        """
        return self._chunkwise_dcmi_set(0xa, mci + '\x00')

    def get_asset_tag(self):
        """Get the system asset tag, per DCMI specification

        :returns: The asset tag
        """
        return self._chunkwise_dcmi_fetch(6)

    def set_asset_tag(self, tag):
        """Set the asset tag value

        """
        return self._chunkwise_dcmi_set(8, tag)

    def _chunkwise_dcmi_fetch(self, command):
        szdata = self.xraw_command(
            netfn=0x2c, command=command, data=(0xdc, 0, 0))
        totalsize = ord(szdata['data'][1])
        chksize = 0xf
        offset = 0
        retstr = ''
        while offset < totalsize:
            if (offset + chksize) > totalsize:
                chksize = totalsize - offset
            chk = self.xraw_command(
                netfn=0x2c, command=command, data=(0xdc, offset, chksize))
            retstr += chk['data'][2:]
            offset += chksize
        return retstr

    def _chunkwise_dcmi_set(self, command, data):
        chunks = [data[i:i+15] for i in xrange(0, len(data), 15)]
        offset = 0
        for chunk in chunks:
            chunk = bytearray(chunk, 'utf-8')
            cmddata = bytearray((0xdc, offset, len(chunk)))
            cmddata += chunk
            self.xraw_command(netfn=0x2c, command=command, data=cmddata)

    def set_channel_access(self, channel=None,
                           access_update_mode='non_volatile',
                           alerting=False, per_msg_auth=False,
                           user_level_auth=False, access_mode='always',
                           privilege_update_mode='non_volatile',
                           privilege_level='administrator'):
        """Set channel access

        :param channel: number [1:7]

        :param access_update_mode:
            dont_change  = don't set or change Channel Access
            non_volatile = set non-volatile Channel Access
            volatile     = set volatile (active) setting of Channel Access

        :param alerting: PEF Alerting Enable/Disable
        True  = enable PEF Alerting
        False = disable PEF Alerting on this channel
                (Alert Immediate command can still be used to generate alerts)

        :param per_msg_auth: Per-message Authentication
        True  = enable
        False = disable Per-message Authentication. [Authentication required to
                activate any session on this channel, but authentication not
                used on subsequent packets for the session.]

        :param user_level_auth: User Level Authentication Enable/Disable.
        True  = enable User Level Authentication. All User Level commands are
            to be authenticated per the Authentication Type that was
            negotiated when the session was activated.
        False = disable User Level Authentication. Allow User Level commands to
            be executed without being authenticated.
            If the option to disable User Level Command authentication is
            accepted, the BMC will accept packets with Authentication Type
            set to None if they contain user level commands.
            For outgoing packets, the BMC returns responses with the same
            Authentication Type that was used for the request.

        :param access_mode: Access Mode for IPMI messaging
        (PEF Alerting is enabled/disabled separately from IPMI messaging)
        disabled = disabled for IPMI messaging
        pre_boot = pre-boot only channel only available when system is in a
                powered down state or in BIOS prior to start of boot.
        always   = channel always available regardless of system mode.
                BIOS typically dedicates the serial connection to the BMC.
        shared   = same as always available, but BIOS typically leaves the
                serial port available for software use.

        :param privilege_update_mode: Channel Privilege Level Limit.
            This value sets the maximum privilege level
            that can be accepted on the specified channel.
            dont_change  = don't set or change channel Privilege Level Limit
            non_volatile = non-volatile Privilege Level Limit according
            volatile     = volatile setting of Privilege Level Limit

        :param privilege_level: Channel Privilege Level Limit
            * reserved      = unused
            * callback
            * user
            * operator
            * administrator
            * proprietary   = used by OEM
        """
        if channel is None:
            channel = self.get_network_channel()
        data = []
        data.append(channel & 0b00001111)
        access_update_modes = {
            'dont_change': 0,
            'non_volatile': 1,
            'volatile': 2,
            #'reserved': 3
        }
        b = 0
        b |= (access_update_modes[access_update_mode] << 6) & 0b11000000
        if alerting:
            b |= 0b00100000
        if per_msg_auth:
            b |= 0b00010000
        if user_level_auth:
            b |= 0b00001000
        access_modes = {
            'disabled': 0,
            'pre_boot': 1,
            'always': 2,
            'shared': 3,
        }
        b |= access_modes[access_mode] & 0b00000111
        data.append(b)
        b = 0
        privilege_update_modes = {
            'dont_change': 0,
            'non_volatile': 1,
            'volatile': 2,
            #'reserved': 3
        }
        b |= (privilege_update_modes[privilege_update_mode] << 6) & 0b11000000
        privilege_levels = {
            'reserved': 0,
            'callback': 1,
            'user': 2,
            'operator': 3,
            'administrator': 4,
            'proprietary': 5,
            # 'no_access': 0x0F,
        }
        b |= privilege_levels[privilege_level] & 0b00000111
        data.append(b)
        response = self.raw_command(netfn=0x06, command=0x40, data=data)
        if 'error' in response:
            raise Exception(response['error'])
        return True

    def get_channel_access(self, channel=None, read_mode='volatile'):
        """Get channel access

        :param channel: number [1:7]
        :param read_mode:
        non_volatile  = get non-volatile Channel Access
        volatile      = get present volatile (active) setting of Channel Access

        :return: A Python dict with the following keys/values:
          {
            - alerting:
            - per_msg_auth:
            - user_level_auth:
            - access_mode:{
                0: 'disabled',
                1: 'pre_boot',
                2: 'always',
                3: 'shared'
              }
            - privilege_level: {
                1: 'callback',
                2: 'user',
                3: 'operator',
                4: 'administrator',
                5: 'proprietary',
              }
           }
        """
        if channel is None:
            channel = self.get_network_channel()
        data = []
        data.append(channel & 0b00001111)
        b = 0
        read_modes = {
            'non_volatile': 1,
            'volatile': 2,
        }
        b |= (read_modes[read_mode] << 6) & 0b11000000
        data.append(b)

        response = self.raw_command(netfn=0x06, command=0x41, data=data)
        if 'error' in response:
            raise Exception(response['error'])

        data = response['data']
        if len(data) != 2:
            raise Exception('expecting 2 data bytes')

        r = {}
        r['alerting'] = data[0] & 0b10000000 > 0
        r['per_msg_auth'] = data[0] & 0b01000000 > 0
        r['user_level_auth'] = data[0] & 0b00100000 > 0
        access_modes = {
            0: 'disabled',
            1: 'pre_boot',
            2: 'always',
            3: 'shared'
        }
        r['access_mode'] = access_modes[data[0] & 0b00000011]
        privilege_levels = {
            0: 'reserved',
            1: 'callback',
            2: 'user',
            3: 'operator',
            4: 'administrator',
            5: 'proprietary',
            #0x0F: 'no_access'
        }
        r['privilege_level'] = privilege_levels[data[1] & 0b00001111]
        return r

    def get_channel_info(self, channel=None):
        """Get channel info

        :param channel: number [1:7]

        :return:
        session_support:
            no_session: channel is session-less
            single: channel is single-session
            multi: channel is multi-session
            auto: channel is session-based (channel could alternate between
                single- and multi-session operation, as can occur with a
                serial/modem channel that supports connection mode auto-detect)
        """
        if channel is None:
            channel = self.get_network_channel()
        data = []
        data.append(channel & 0b00001111)
        response = self.raw_command(netfn=0x06, command=0x42, data=data)
        if 'error' in response:
            raise Exception(response['error'])
        data = response['data']
        if len(data) != 9:
            raise Exception('expecting 10 data bytes got: {0}'.format(data))
        r = {}
        r['Actual channel'] = data[0] & 0b00000111
        channel_medium_types = {
            0: 'reserved',
            1: 'IPMB',
            2: 'ICMB v1.0',
            3: 'ICMB v0.9',
            4: '802.3 LAN',
            5: 'Asynch. Serial/Modem (RS-232)',
            6: 'Other LAN',
            7: 'PCI SMBus',
            8: 'SMBus v1.0/1.1',
            9: 'SMBus v2.0',
            0x0a: 'reserved for USB 1.x',
            0x0b: 'reserved for USB 2.x',
            0x0c: 'System Interface (KCS, SMIC, or BT)',
            ## 60h-7Fh: OEM
            ## all other  reserved
        }
        t = data[1] & 0b01111111
        if t in channel_medium_types:
            r['Channel Medium type'] = channel_medium_types[t]
        else:
            r['Channel Medium type'] = 'OEM {:02X}'.format(t)
        r['5-bit Channel IPMI Messaging Protocol Type'] = data[2] & 0b00001111
        session_supports = {
            0: 'no_session',
            1: 'single',
            2: 'multi',
            3: 'auto'
        }
        r['session_support'] = session_supports[(data[3] & 0b11000000) >> 6]
        r['active_session_count'] = data[3] & 0b00111111
        r['Vendor ID'] = [data[4], data[5], data[6]]
        r['Auxiliary Channel Info'] = [data[7], data[8]]
        return r

    def set_user_access(self, uid, channel=None, callback=False,
                        link_auth=True, ipmi_msg=True, privilege_level='user'):
        """Set user access

        :param uid: user number [1:16]

        :param channel: number [1:7]

        :parm callback: User Restricted to Callback
        False = User Privilege Limit is determined by the User Privilege Limit
            parameter, below, for both callback and non-callback connections.
        True  = User Privilege Limit is determined by the User Privilege Limit
            parameter for callback connections, but is restricted to Callback
            level for non-callback connections. Thus, a user can only initiate
            a Callback when they 'call in' to the BMC, but once the callback
            connection has been made, the user could potentially establish a
            session as an Operator.

        :param link_auth: User Link authentication
        enable/disable (used to enable whether this
        user's name and password information will be used for link
        authentication, e.g. PPP CHAP) for the given channel. Link
        authentication itself is a global setting for the channel and is
        enabled/disabled via the serial/modem configuration parameters.

        :param ipmi_msg: User IPMI Messaginge:
        (used to enable/disable whether
        this user's name and password information will be used for IPMI
        Messaging. In this case, 'IPMI Messaging' refers to the ability to
        execute generic IPMI commands that are not associated with a
        particular payload type. For example, if IPMI Messaging is disabled for
        a user, but that user is enabled for activatallow_authing the SOL
        payload type, then IPMI commands associated with SOL and session
        management, such as Get SOL Configuration Parameters and Close Session
        are available, but generic IPMI commands such as Get SEL Time are
        unavailable.)

        :param privilege_level:
        User Privilege Limit. (Determines the maximum privilege level that the
        user is allowed to switch to on the specified channel.)
            * callback
            * user
            * operator
            * administrator
            * proprietary
            * no_access
        """
        if channel is None:
            channel = self.get_network_channel()
        b = 0b10000000
        if callback:
            b |= 0b01000000
        if link_auth:
            b |= 0b00100000
        if ipmi_msg:
            b |= 0b00010000
        b |= channel & 0b00001111
        privilege_levels = {
            'reserved': 0,
            'callback': 1,
            'user': 2,
            'operator': 3,
            'administrator': 4,
            'proprietary': 5,
            'no_access': 0x0F,
        }
        data = [b, uid & 0b00111111,
                privilege_levels[privilege_level] & 0b00001111, 0]
        response = self.raw_command(netfn=0x06, command=0x43, data=data)
        if 'error' in response:
            raise Exception(response['error'])
        return True

    def get_user_access(self, uid, channel=None):
        """Get user access

        :param uid: user number [1:16]
        :param channel: number [1:7]

        :return:
        channel_info:
            max_user_count = maximum number of user IDs on this channel
            enabled_users = count of User ID slots presently in use
            users_with_fixed_names = count of user IDs with fixed names

        access:
            callback
            link_auth
            ipmi_msg
            privilege_level: [reserved, callback, user,
                              operatorm administrator, proprietary, no_access]
        """
        ## user access available during call-in or callback direct connection
        if channel is None:
            channel = self.get_network_channel()
        data = [channel, uid]
        response = self.raw_command(netfn=0x06, command=0x44, data=data)
        if 'error' in response:
            raise Exception(response['error'])
        data = response['data']
        if len(data) != 4:
            raise Exception('expecting 4 data bytes')
        r = {'channel_info': {}, 'access': {}}
        r['channel_info']['max_user_count'] = data[0]
        r['channel_info']['enabled_users'] = data[1] & 0b00111111
        r['channel_info']['users_with_fixed_names'] = data[2] & 0b00111111
        r['access']['callback'] = (data[3] & 0b01000000) != 0
        r['access']['link_auth'] = (data[3] & 0b00100000) != 0
        r['access']['ipmi_msg'] = (data[3] & 0b00010000) != 0
        privilege_levels = {
            0: 'reserved',
            1: 'callback',
            2: 'user',
            3: 'operator',
            4: 'administrator',
            5: 'proprietary',
            0x0F: 'no_access'
        }
        r['access']['privilege_level'] = privilege_levels[data[3] & 0b00001111]
        return r

    def set_user_name(self, uid, name):
        """Set user name

        :param uid: user number [1:16]
        :param name: username (limit of 16bytes)
        """
        data = [uid]
        if len(name) > 16:
            raise Exception('name must be less than or = 16 chars')
        name = name.ljust(16, "\x00")
        data.extend([ord(x) for x in name])
        response = self.raw_command(netfn=0x06, command=0x45, data=data)
        if 'error' in response:
            raise Exception(response['error'])
        return True

    def get_user_name(self, uid, return_none_on_error=True):
        """Get user name

        :param uid: user number [1:16]
        :param return_none_on_error: return None on error
            TODO: investigate return code on error
        """
        response = self.raw_command(netfn=0x06, command=0x46, data=(uid,))
        if 'error' in response:
            if return_none_on_error:
                return None
            raise Exception(response['error'])
        name = None
        if 'data' in response:
            data = response['data']
            if len(data) == 16:
                # convert int array to string
                n = ''.join(chr(data[i]) for i in range(0, len(data)))
                # remove padded \x00 chars
                n = n.rstrip("\x00")
                if len(n) > 0:
                    name = n
        return name

    def set_user_password(self, uid, mode='set_password', password=None):
        """Set user password and (modes)

        :param uid: id number of user.  see: get_names_uid()['name']

        :param mode:
            disable       = disable user connections
            enable        = enable user connections
            set_password  = set or ensure password
            test_password = test password is correct

        :param password: max 16 char string
            (optional when mode is [disable or enable])

        :return:
            True on success
            when mode = test_password, return False on bad password
        """
        mode_mask = {
            'disable': 0,
            'enable': 1,
            'set_password': 2,
            'test_password': 3
        }
        data = [uid, mode_mask[mode]]
        if password:
            password = str(password)
            if 21 > len(password) > 16:
                password = password.ljust(20, '\x00')
                data[0] |= 0b10000000
            elif len(password) > 20:
                raise Exception('password has limit of 20 chars')
            else:
                password = password.ljust(16, "\x00")
            data.extend([ord(x) for x in password])
        response = self.raw_command(netfn=0x06, command=0x47, data=data)
        if 'error' in response:
            if mode == 'test_password':
                # return false if password test failed
                return False
            raise Exception(response['error'])
        return True

    def get_channel_max_user_count(self, channel=None):
        """Get max users in channel (helper)

        :param channel: number [1:7]
        :return: int -- often 16
        """
        if channel is None:
            channel = self.get_network_channel()
        access = self.get_user_access(channel=channel, uid=1)
        return access['channel_info']['max_user_count']

    def get_user(self, uid, channel=None):
        """Get user (helper)

        :param uid: user number [1:16]
        :param channel: number [1:7]

        :return:
            name: (str)
            uid: (int)
            channel: (int)
            access:
                callback (bool)
                link_auth (bool)
                ipmi_msg (bool)
                privilege_level: (str)[callback, user, operatorm administrator,
                                       proprietary, no_access]
        """
        if channel is None:
            channel = self.get_network_channel()
        name = self.get_user_name(uid)
        access = self.get_user_access(uid, channel)
        data = {'name': name, 'uid': uid, 'channel': channel,
                'access': access['access']}
        return data

    def get_name_uids(self, name, channel=None):
        """get list of users (helper)

        :param channel: number [1:7]

        :return: list of users
        """
        if channel is None:
            channel = self.get_network_channel()
        uid_list = []
        max_ids = self.get_channel_max_user_count(channel)
        for uid in range(1, max_ids):
            if name == self.get_user_name(uid=uid):
                uid_list.append(uid)
        return uid_list

    def get_users(self, channel=None):
        """get list of users and channel access information (helper)

        :param channel: number [1:7]

        :return:
            name: (str)
            uid: (int)
            channel: (int)
            access:
                callback (bool)
                link_auth (bool)
                ipmi_msg (bool)
                privilege_level: (str)[callback, user, operatorm administrator,
                                       proprietary, no_access]
        """
        if channel is None:
            channel = self.get_network_channel()
        names = {}
        max_ids = self.get_channel_max_user_count(channel)
        for uid in range(1, max_ids+1):
            name = self.get_user_name(uid=uid)
            if name is not None:
                names[uid] = self.get_user(uid=uid, channel=channel)
        return names

    def create_user(self, uid, name, password, channel=None, callback=False,
                    link_auth=True, ipmi_msg=True,
                    privilege_level='user'):
        """create/ensure a user is created with provided settings (helper)

        :param privilege_level:
            User Privilege Limit. (Determines the maximum privilege level that
            the user is allowed to switch to on the specified channel.)
            * callback
            * user
            * operator
            * administrator
            * proprietary
            * no_access
        """
        # current user might be trying to update.. dont disable
        # set_user_password(uid, password, mode='disable')
        if channel is None:
            channel = self.get_network_channel()
        self.set_user_name(uid, name)
        self.set_user_access(uid, channel, callback=callback,
                             link_auth=link_auth, ipmi_msg=ipmi_msg,
                             privilege_level=privilege_level)
        self.set_user_password(uid, password=password)
        self.set_user_password(uid, mode='enable', password=password)
        return True

    def user_delete(self, uid, channel=None):
        """Delete user (helper)

        Note that in IPMI, user 'deletion' isn't a concept.  This function
        will make a best effort to provide the expected result (e.g.
        web interfaces skipping names and ipmitool skipping as well.

        :param uid: user number [1:16]
        :param channel: number [1:7]
        """
        # TODO(jjohnson2): Provide OEM extensibility to cover user deletion
        if channel is None:
            channel = self.get_network_channel()
        self.set_user_password(uid, mode='disable', password=None)
        # TODO(steveweber) perhaps should set user access on all channels
        # so new users dont get extra access
        self.set_user_access(uid, channel=channel, callback=False,
                             link_auth=False, ipmi_msg=False,
                             privilege_level='no_access')
        try:
            # First try to set name to all \x00 explicitly
            self.set_user_name(uid, '')
        except Exception:
            # An invalid data field in request  is frequently reported.
            # however another convention that exists is all '\xff'
            # if this fails, pass up the error so that calling code knows
            # that the deletion did not go as planned for now
            self.set_user_name(uid, '\xff' * 16)
        return True

    def disable_user(self, uid, mode):
        """Disable User

        Just disable the User.
        This will not disable the password or revoke privileges.

        :param uid: user number [1:16]
        :param mode:
            disable       = disable user connections
            enable        = enable user connections
        """
        self.set_user_password(uid, mode)
        return True

    def get_firmware(self):
        """Retrieve OEM Firmware information
        """
        self.oem_init()
        mcinfo = self.xraw_command(netfn=6, command=1)
        bmcver = '{0}.{1}'.format(
            ord(mcinfo['data'][2]), hex(ord(mcinfo['data'][3]))[2:])
        return self._oem.get_oem_firmware(bmcver)

    def get_capping_enabled(self):
        """Get PSU based power capping status

        :return: True if enabled and False if disabled
        """
        self.oem_init()
        return self._oem.get_oem_capping_enabled()

    def set_capping_enabled(self, enable):
        """Set PSU based power capping

        :param enable: True for enable and False for disable
        """
        self.oem_init()
        return self._oem.set_oem_capping_enabled(enable)

    def get_remote_kvm_available(self):
        """Get remote KVM availability
        """
        self.oem_init()
        return self._oem.get_oem_remote_kvm_available()

    def get_domain_name(self):
        """Get Domain name
        """
        self.oem_init()
        return self._oem.get_oem_domain_name()

    def set_domain_name(self, name):
        """Set Domain name

        :param name: domain name to be set
        """
        self.oem_init()
        self._oem.set_oem_domain_name(name)

    def get_graphical_console(self):
        """Get graphical console launcher"""
        self.oem_init()
        return self._oem.get_graphical_console()

    def attach_remote_media(self, url, username=None, password=None):
        """Attach remote media by url

        Given a url, attach remote media (cd/usb image) to the target system.

        :param url:  URL to indicate where to find image (protocol support
                     varies by BMC)
        :param username: Username for endpoint to use when accessing the URL.
                         If applicable, 'domain' would be indicated by '@' or
                         '\' syntax.
        :param password: Password for endpoint to use when accessing the URL.
        """
        self.oem_init()
        self._oem.attach_remote_media(url, username, password)

    def detach_remote_media(self):
        self.oem_init()
        self._oem.detach_remote_media()
