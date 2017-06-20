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
import pyghmi.ipmi.sdr as sdr
import struct

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
    perminfo = ord(rsp['data'][1])
    health = pygconst.Health.Ok
    states = []
    if len(rsp['data']) == 4:  # different gens handled rc differently
        rsp['data'] = b'\x00' + bytes(rsp['data'])
    if sz == 6:  # FPC
        permfail = ('\x02', '\x03')
    elif sz == 2:  # SMM
        permfail = ('\x02',)
    if rsp['data'][4] in permfail:
        states.append('Insufficient Power')
        health = pygconst.Health.Failed
    if perminfo & 0x40:
        states.append('Node Fault')
        health = pygconst.Health.Failed
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
