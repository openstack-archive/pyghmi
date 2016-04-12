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

import pyghmi.ipmi.sdr as sdr
import struct


def fpc_read_ac_input(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x90, data=(1,))
    rsp = rsp['data']
    return struct.unpack_from('<H', rsp[3:5])[0]


def fpc_read_dc_output(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x90, data=(2,))
    rsp = rsp['data']
    return struct.unpack_from('<H', rsp[3:5])[0]


def fpc_read_fan_power(ipmicmd):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0x90, data=(3,))
    rsp = rsp['data']
    rsp += '\x00'
    return struct.unpack_from('<I', rsp[1:])[0] / 100.0


def fpc_read_psu_fan(ipmicmd, number):
    rsp = ipmicmd.xraw_command(netfn=0x32, command=0xa5, data=(number,))
    rsp = rsp['data']
    return struct.unpack_from('<H', rsp[:2])[0]


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
        'elements': 6,
    }
}


def get_sensor_names():
    global fpc_sensors
    for name in fpc_sensors:
        sensor = fpc_sensors[name]
        if 'elements' in sensor:
            for elemidx in xrange(sensor['elements']):
                elemidx += 1
                yield '{0} {1}'.format(name, elemidx)
        else:
            yield name


def get_sensor_descriptions():
    global fpc_sensors
    for name in fpc_sensors:
        sensor = fpc_sensors[name]
        if 'elements' in sensor:
            for elemidx in xrange(sensor['elements']):
                elemidx += 1
                yield {'name': '{0} {1}'.format(name, elemidx),
                       'type': sensor['type']}
        else:
            yield {'name': name, 'type': sensor['type']}


def get_sensor_reading(name, ipmicmd):
    value = None
    sensor = None
    if name in fpc_sensors and 'elements' not in fpc_sensors[name]:
        sensor = fpc_sensors[name]
        value = sensor['provider'](ipmicmd)
    else:
        bname, _, idx = name.rpartition(' ')
        idx = int(idx)
        if bname in fpc_sensors and idx <= fpc_sensors[bname]['elements']:
            sensor = fpc_sensors[bname]
            value = sensor['provider'](ipmicmd, idx)
    if sensor is not None:
        return sdr.SensorReading({'name': name, 'imprecision': None,
                                  'value': value, 'states': [],
                                  'state_ids': [], 'health': 0,
                                  'type': sensor['type']},
                                 sensor['units'])
    raise Exception('Sensor not found: ' + name)
