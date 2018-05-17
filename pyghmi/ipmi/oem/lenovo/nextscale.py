# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2017 Lenovo
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
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.private.session as ipmisession
import pyghmi.ipmi.sdr as sdr
import pyghmi.util.webclient as webclient
import struct
import urllib
import weakref
from xml.etree.ElementTree import fromstring
import zipfile

try:
    range = xrange
except NameError:
    pass


def fpc_read_ac_input(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x90, data=(1,))
    rsp = rsp['data']
    if len(rsp) == 6:
        rsp = b'\x00' + bytes(rsp)
    return struct.unpack_from('<H', rsp[3:5])[0]


def fpc_read_dc_output(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x90, data=(2,))
    rsp = rsp['data']
    if len(rsp) == 6:
        rsp = b'\x00' + bytes(rsp)
    return struct.unpack_from('<H', rsp[3:5])[0]


def fpc_read_fan_power(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x90, data=(3,))
    rsp = rsp['data']
    rsp += '\x00'
    return struct.unpack_from('<I', rsp[1:])[0] / 100.0


def fpc_read_psu_fan(ipmicmd, number, sz):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0xa5, data=(number,))
    rsp = rsp['data']
    return struct.unpack_from('<H', rsp[:2])[0]


def fpc_get_psustatus(ipmicmd, number, sz):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x91)
    mask = 1 << (number - 1)
    if len(rsp['data']) == 6:
        statdata = bytearray([0])
    else:
        statdata = bytearray()
    statdata += bytearray(rsp['data'])
    presence = statdata[3] & mask == mask
    pwrgood = statdata[4] & mask == mask
    throttle = (statdata[6] | statdata[2]) & mask == mask
    health = pygconst.Health.Ok
    states = []
    if presence and not pwrgood:
        health = pygconst.Health.Critical
        states.append('Power input lost')
    if throttle:
        health = pygconst.Health.Critical
        states.append('Throttled')
    if presence:
        states.append('Present')
    else:
        states.append('Absent')
        health = pygconst.Health.Critical
    return (health, states)


def fpc_get_nodeperm(ipmicmd, number, sz):
    try:
        rsp = ipmicmd.xraw_command(netfn=0x32, command=0xa7, data=(number,))
    except pygexc.IpmiException as ie:
        if ie.ipmicode == 0xd5:  # no node present
            return (pygconst.Health.Ok, ['Absent'])
        raise
    health = pygconst.Health.Ok
    states = []
    if len(rsp['data']) == 4:  # different gens handled rc differently
        rsp['data'] = b'\x00' + bytes(rsp['data'])
    elif len(rsp['data']) == 6:  # New FPC format
        rsp['data'] = rsp['data'][:2] + rsp['data'][3:]
    perminfo = ord(rsp['data'][1])
    if sz == 6:  # FPC
        permfail = ('\x02', '\x03')
    elif sz == 2:  # SMM
        permfail = ('\x02',)
    if perminfo & 0x20:
        if rsp['data'][4] in permfail:
            states.append('Insufficient Power')
            health = pygconst.Health.Failed
        elif rsp['data'][3:5] != '\x00\x00':
            states.append('No Power Permission')
            health = pygconst.Health.Failed
    if perminfo & 0x40:
        states.append('Node Fault')
        health = pygconst.Health.Failed
    if rsp['data'][3:5] == '\x00\x00':
        states.append('Absent')
    return (health, states)


def fpc_read_powerbank(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0xa2)
    return struct.unpack_from('<H', rsp['data'][3:])[0]


fpc_sensors = {
    'AC Power': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_ac_input,
    },
    'DC Power': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_dc_output,
    },
    'Fan Power': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_fan_power
    },
    'PSU Fan Speed': {
        'type': 'Fan',
        'units': 'RPM',
        'provider': fpc_read_psu_fan,
        'elements': 1,
    },
    'Total Power Capacity': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_powerbank,
    },
    'Node Power Permission': {
        'type': 'Management Subsystem Health',
        'returns': 'tuple',
        'units': None,
        'provider': fpc_get_nodeperm,
        'elements': 2,
    },
    'Power Supply': {
        'type': 'Power Supply',
        'returns': 'tuple',
        'units': None,
        'provider': fpc_get_psustatus,
        'elements': 1,
    }
}


def get_sensor_names(size):
    global fpc_sensors
    for name in fpc_sensors:
        if size == 2 and name in ('Fan Power', 'Total Power Capacity'):
            continue
        sensor = fpc_sensors[name]
        if 'elements' in sensor:
            for elemidx in range(sensor['elements'] * size):
                elemidx += 1
                yield '{0} {1}'.format(name, elemidx)
        else:
            yield name


def get_sensor_descriptions(size):
    global fpc_sensors
    for name in fpc_sensors:
        if size == 2 and name in ('Fan Power', 'Total Power Capacity'):
            continue
        sensor = fpc_sensors[name]
        if 'elements' in sensor:
            for elemidx in range(sensor['elements'] * size):
                elemidx += 1
                yield {'name': '{0} {1}'.format(name, elemidx),
                       'type': sensor['type']}
        else:
            yield {'name': name, 'type': sensor['type']}


def get_fpc_firmware(bmcver, ipmicmd, fpcorsmm):
    mymsg = ipmicmd.xraw_command(netfn=0x32, command=0xa8)
    builddata = bytearray(mymsg['data'])
    name = None
    if fpcorsmm == 2:  # SMM
        name = 'SMM'
        buildid = '{0}{1}{2}{3}{4}{5}{6}'.format(
            *[chr(x) for x in builddata[-7:]])
    elif len(builddata) == 8:
        builddata = builddata[1:]  # discard the 'completion code'
        name = 'FPC'
        buildid = '{0}{1}'.format(builddata[-2], chr(builddata[-1]))
    yield (name, {'version': bmcver, 'build': buildid})
    yield ('PSOC', {'version': '{0}.{1}'.format(builddata[2], builddata[3])})


def get_sensor_reading(name, ipmicmd, sz):
    value = None
    sensor = None
    health = pygconst.Health.Ok
    states = []
    if name in fpc_sensors and 'elements' not in fpc_sensors[name]:
        sensor = fpc_sensors[name]
        value = sensor['provider'](ipmicmd)
    else:
        bnam, _, idx = name.rpartition(' ')
        idx = int(idx)
        if bnam in fpc_sensors and idx <= fpc_sensors[bnam]['elements'] * sz:
            sensor = fpc_sensors[bnam]
            if 'returns' in sensor:
                health, states = sensor['provider'](ipmicmd, idx, sz)
            else:
                value = sensor['provider'](ipmicmd, idx, sz)
    if sensor is not None:
        return sdr.SensorReading({'name': name, 'imprecision': None,
                                  'value': value, 'states': states,
                                  'state_ids': [], 'health': health,
                                  'type': sensor['type']},
                                 sensor['units'])
    raise Exception('Sensor not found: ' + name)


class SMMClient(object):

    def __init__(self, ipmicmd):
        self.ipmicmd = weakref.proxy(ipmicmd)
        self.smm = ipmicmd.bmc
        self.username = ipmicmd.ipmi_session.userid
        self.password = ipmicmd.ipmi_session.password
        self._wc = None

    def reseat_bay(self, bay):
        self.ipmicmd.xraw_command(netfn=0x32, command=0xa4,
                                  data=[int(bay), 2])

    def process_fru(self, fru):
        # TODO(jjohnson2): can also get EIOM, SMM, and riser data if warranted
        fru['Serial Number'] = self.ipmicmd.xraw_command(
            netfn=0x32, command=0xb0, data=(5, 1))['data'][:].strip(
                ' \x00\xff').replace('\xff', '')
        fru['Model'] = self.ipmicmd.xraw_command(
            netfn=0x32, command=0xb0, data=(5, 0))['data'][:].strip(
                ' \x00\xff').replace('\xff', '')
        return fru

    def get_webclient(self):
        cv = self.ipmicmd.certverify
        wc = webclient.SecureHTTPConnection(self.smm, 443, verifycallback=cv)
        wc.connect()
        loginform = urllib.urlencode({'user': self.username,
                                      'password': self.password})
        wc.request('POST', '/data/login', loginform)
        rsp = wc.getresponse()
        if rsp.status != 200:
            raise Exception(rsp.read())
        authdata = rsp.read()
        authdata = fromstring(authdata)
        for data in authdata.findall('authResult'):
            if int(data.text) != 0:
                raise Exception("Firmware update already in progress")
        for data in authdata.findall('forwardUrl'):
            if 'renew' in data.text:
                raise Exception("Account password has expired on remote "
                                "device")
        self.st1 = None
        self.st2 = None
        for data in authdata.findall('st1'):
            self.st1 = data.text
        for data in authdata.findall('st2'):
            self.st2 = data.text
        if not self.st2:
            # This firmware puts tokens in the html file, parse that
            wc.request('GET', '/index.html')
            rsp = wc.getresponse()
            if rsp.status != 200:
                raise Exception(rsp.read())
            indexhtml = rsp.read()
            for line in indexhtml.split('\n'):
                if '"ST1"' in line:
                    self.st1 = line.split()[-1].replace(
                        '"', '').replace(',', '')
                if '"ST2"' in line:
                    self.st2 = line.split()[-1].replace(
                        '"', '').replace(',', '')
        wc.set_header('ST2', self.st2)
        return wc

    def set_hostname(self, hostname):
        self.wc.request('POST', '/data', 'set=hostname:' + hostname)
        rsp = self.wc.getresponse()
        if rsp.status != 200:
            raise Exception(rsp.read())
        rsp.read()
        self.logout()

    def get_hostname(self):
        currinfo = self.get_netinfo()
        self.logout()
        for data in currinfo.find('netConfig').findall('hostname'):
            return data.text

    def get_netinfo(self):
        self.wc.request('POST', '/data', 'get=hostname')
        rsp = self.wc.getresponse()
        data = rsp.read()
        if rsp.status == 400:
            self.wc.request('POST', '/data?get=hostname', '')
            rsp = self.wc.getresponse()
            data = rsp.read()
        if rsp.status != 200:
            raise Exception(data)
        currinfo = fromstring(data)
        return currinfo

    def set_domain(self, domain):
        self.wc.request('POST', '/data', 'set=dnsDomain:' + domain)
        rsp = self.wc.getresponse()
        if rsp.status != 200:
            raise Exception(rsp.read())
        rsp.read()
        self.logout()

    def get_domain(self):
        currinfo = self.get_netinfo()
        self.logout()
        for data in currinfo.find('netConfig').findall('dnsDomain'):
            return data.text

    def get_ntp_enabled(self, variant):
        self.wc.request('POST', '/data', 'get=ntpOpMode')
        rsp = self.wc.getresponse()
        info = fromstring(rsp.read())
        self.logout()
        for data in info.findall('ntpOpMode'):
            return data.text == '1'

    def set_ntp_enabled(self, enabled):
        self.wc.request('POST', '/data', 'set=ntpOpMode:{0}'.format(
            1 if enabled else 0))
        rsp = self.wc.getresponse()
        result = rsp.read()
        self.logout()
        if '<status>ok</status>' not in result:
            raise Exception("Unrecognized result: " + result)

    def set_ntp_server(self, server, index):
        self.wc.request('POST', '/data', 'set=ntpServer{0}:{1}'.format(
            index + 1, server))
        rsp = self.wc.getresponse()
        result = rsp.read()
        if '<status>ok</status>' not in result:
            raise Exception("Unrecognized result: " + result)
        self.logout()
        return True

    def get_ntp_servers(self):
        self.wc.request(
            'POST', '/data', 'get=ntpServer1,ntpServer2,ntpServer3')
        rsp = self.wc.getresponse()
        result = fromstring(rsp.read())
        srvs = []
        for data in result.findall('ntpServer1'):
            srvs.append(data.text)
        for data in result.findall('ntpServer2'):
            srvs.append(data.text)
        for data in result.findall('ntpServer3'):
            srvs.append(data.text)
        self.logout()
        return srvs

    def update_firmware(self, filename, data=None, progress=None, bank=None):
        if progress is None:
            progress = lambda x: True
        if not data and zipfile.is_zipfile(filename):
            z = zipfile.ZipFile(filename)
            for tmpname in z.namelist():
                if tmpname.endswith('.rom'):
                    filename = tmpname
                    data = z.open(filename)
                    break
        progress({'phase': 'upload', 'progress': 0.0})
        url = self.wc  # this is just to get self.st1 initted
        self.wc.request('POST', '/data', 'set=fwType:10')  # SMM firmware
        rsp = self.wc.getresponse()
        rsp.read()
        url = '/fwupload/fwupload.esp?ST1={0}'.format(self.st1)
        self.wc.upload(url, filename, data, formname='fileUpload',
                       otherfields={'preConfig': 'on'})
        progress({'phase': 'validating', 'progress': 0.0})
        url = '/data'
        self.wc.request('POST', url, 'get=fwVersion,spfwInfo')
        rsp = self.wc.getresponse()
        rsp.read()
        if rsp.status != 200:
            raise Exception('Error validating firmware')
        progress({'phase': 'apply', 'progress': 0.0})
        self.wc.request('POST', '/data', 'set=fwUpdate:1')
        rsp = self.wc.getresponse()
        rsp.read()
        complete = False
        while not complete:
            ipmisession.Session.pause(3)
            self.wc.request('POST', '/data', 'get=fwProgress,fwUpdate')
            rsp = self.wc.getresponse()
            progdata = rsp.read()
            if rsp.status != 200:
                raise Exception('Error applying firmware')
            progdata = fromstring(progdata)
            if progdata.findall('fwUpdate')[0].text == 'invalid signature':
                raise Exception('Firmware signature invalid')
            percent = float(progdata.findall('fwProgress')[0].text)

            progress({'phase': 'apply',
                      'progress': percent})
            complete = percent >= 100.0
        return 'complete'

    def logout(self):
        self.wc.request('POST', '/data/logout', None)
        rsp = self.wc.getresponse()
        rsp.read()
        self._wc = None

    @property
    def wc(self):
        if not self._wc or self._wc.broken:
            self._wc = self.get_webclient()
        return self._wc
