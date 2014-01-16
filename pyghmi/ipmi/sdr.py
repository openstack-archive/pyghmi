# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf8

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

# This module provides access to SDR offered by a BMC
# This data is common between 'sensors' and 'inventory' modules since SDR
# is both used to enumerate sensors for sensor commands and FRU ids for FRU
# commands

# For now, we will not offer persistent SDR caching as we do in xCAT's IPMI
# code.  Will see if it is adequate to advocate for high object reuse in a
# persistent process for the moment.

# Focus is at least initially on the aspects that make the most sense for a
# remote client to care about.  For example, smbus information is being
# skipped for now

import math
import pyghmi.exceptions as exc
import pyghmi.ipmi.command as ipmicmd
import pyghmi.ipmi.private.constants as ipmiconstants
import struct

TYPE_UNKNOWN = 0
TYPE_SENSOR = 1
TYPE_FRU = 2


def _round_sigbits(value, sigbits):
        bwidth = int(math.ceil(math.log(value, 2)))
        if bwidth > sigbits:
            # if the result is wider than the significant figures (binary wise)
            # mask out the insignificant figures so that we do not
            # suggest more precision than we have
            mask = ((2 ** sigbits) - 1) << (bwidth - sigbits)
            rounded = value & mask
            if value & (0b1 << (bwidth - sigbits - 1)):
                rounded = rounded + (0b1 << (bwidth - sigbits))
            return rounded
        else:
            return value


def ones_complement(value, bits):
    # utility function to help with the large amount of 2s
    # complement prevalent in ipmi spec
    signbit = 0b1 << (bits - 1)
    if value & signbit:
        #if negative, subtract 1, then take 1s
        #complement given bits width
        return 0 - (value ^ ((0b1 << bits) - 1))
    else:
        return value


def twos_complement(value, bits):
    # utility function to help with the large amount of 2s
    # complement prevalent in ipmi spec
    signbit = 0b1 << (bits - 1)
    if value & signbit:
        #if negative, subtract 1, then take 1s
        #complement given bits width
        return 0 - ((value - 1) ^ ((0b1 << bits) - 1))
    else:
        return value


unit_types = {
    # table 43-15 'sensor unit type codes'
    0: '',
    1: ' °C',
    2: ' °F',
    3: ' K',
    4: ' V',
    5: ' A',
    6: ' W',
    7: ' J',
    8: ' C',
    9: ' VA',
    10: ' nt',
    11: ' lm',
    12: ' lx',
    13: ' cd',
    14: ' kPa',
    15: ' PSI',
    16: ' N',
    17: ' CFM',
    18: ' RPM',
    19: ' Hz',
    20: ' μs',
    21: ' ms',
    22: ' s',
    23: ' min',
    24: ' hr',
    25: ' d',
    26: ' week(s)',
    27: ' mil',
    28: ' inches',
    29: ' ft',
    30: ' cu in',
    31: ' cu feet',
    32: ' mm',
    33: ' cm',
    34: ' m',
    35: ' cu cm',
    36: ' cu m',
    37: ' L',
    38: ' fl. oz.',
    39: ' radians',
    40: ' steradians',
    41: ' revolutions',
    42: ' cycles',
    43: ' g',
    44: ' ounce',
    45: ' lb',
    46: ' ft-lb',
    47: ' oz-in',
    48: ' gauss',
    49: ' gilberts',
    50: ' henry',
    51: ' millihenry',
    52: ' farad',
    53: ' microfarad',
    54: ' ohms',
    55: ' siemens',
    56: ' mole',
    57: ' becquerel',
    58: ' ppm',
    60: ' dB',
    61: ' dBA',
    62: ' dBC',
    63: ' Gy',
    64: ' sievert',
    65: ' color temp deg K',
    66: ' bit',
    67: ' kb',
    68: ' mb',
    69: ' gb',
    70: ' byte',
    71: ' kB',
    72: ' mB',
    73: ' gB',
    74: ' word',
    75: ' dword',
    76: ' qword',
    77: ' line',
    78: ' hit',
    79: ' miss',
    80: ' retry',
    81: ' reset',
    82: ' overrun/overflow',
    83: ' underrun',
    84: ' collision',
    85: ' packets',
    86: ' messages',
    87: ' characters',
    88: ' error',
    89: ' uncorrectable error',
    90: ' correctable error',
    91: ' fatal error',
    92: ' grams',
}

sensor_rates = {
    0: '',
    1: ' per us',
    2: ' per ms',
    3: ' per s',
    4: ' per minute',
    5: ' per hour',
    6: ' per day',
}


class SensorReading(object):

    def __init__(self, reading):
        if 'value' in reading:
            self.value = reading['value']
        else:
            self.value = None
        self.states = reading['states']
        if 'unavailable' in reading:
            self.unavailable = 1
        self.name = reading['name']

    def __repr__(self):
        repr = self.name + ": "
        if self.value is not None:
            repr += str(self.value)
        for state in self.states:
            repr += state + ","
        return repr


class SDREntry(object):
    def __init__(self, entrybytes, reportunsupported=False):
        # ignore record id for now, we only care about the sensor number for
        # moment
        self.reportunsupported = reportunsupported
        if entrybytes[2] != 0x51:
            # only recognize '1.5', the only version defined at time of writing
            raise NotImplementedError
        self.rectype = entrybytes[3]
        self.linearization = None
        #most important to get going are 1, 2, and 11
        self.sdrtype = TYPE_SENSOR  # assume a sensor
        if self.rectype == 1:  # full sdr
            self.full_decode(entrybytes[5:])
        elif self.rectype == 2:  # full sdr
            self.compact_decode(entrybytes[5:])
        elif self.rectype == 8:  # entity association
            self.association_decode(entrybytes[5:])
        elif self.rectype == 0x11:  # FRU locator
            self.fru_decode(entrybytes[5:])
        elif self.rectype == 0x12:  # Management controller
            self.mclocate_decode(entrybytes[5:])
        elif self.rectype == 0xc0:  # OEM format
            self.sdrtype = TYPE_UNKNOWN   # assume undefined
            self.oem_decode(entrybytes[5:])
        elif self.reportunsupported:
            #will remove once I see it stop being thrown for now
            #perhaps need some explicit mode to check for
            #unsupported things, but make do otherwise
            raise NotImplementedError
        else:
            self.sdrtype = TYPE_UNKNOWN

    @property
    def name(self):
        if self.sdrtype == TYPE_SENSOR:
            return self.sensor_name
        elif self.sdrtype == TYPE_FRU:
            return self.fru_name
        else:
            return "UNKNOWN"

    def oem_decode(self, entry):
        mfgid = entry[0] + (entry[1] << 8) + (entry[2] << 16)
        if self.reportunsupported:
            raise NotImplementedError("No support for mfgid %X" % mfgid)

    def mclocate_decode(self, entry):
        # For now, we don't have use for MC locator records
        # we'll ignore them at the moment
        self.sdrtype = TYPE_UNKNOWN
        pass

    def fru_decode(self, entry):
        # table 43-7 FRU Device Locator
        self.sdrtype = TYPE_FRU
        self.fru_name = self.tlv_decode(entry[10], entry[11:])
        self.fru_number = entry[1]

    def association_decode(self, entry):
        # table 43-4 Entity Associaition Record
        #TODO(jbjohnso): actually represent this data
        self.sdrtype = TYPE_UNKNOWN

    def compact_decode(self, entry):
        # table 43-2 compact sensor record
        self._common_decode(entry)
        self.sensor_name = self.tlv_decode(entry[26], entry[27:])

    def _common_decode(self, entry):
        # compact and full are very similar
        # this function handles the common aspects of compact and full
        # offsets from spec, minus 6
        self.sensor_number = entry[2]
        self.entity = ipmiconstants.entity_ids[entry[3]]
        try:
            self.sensor_type = ipmiconstants.sensor_type_codes[entry[7]]
        except KeyError:
            self.sensor_type = "UNKNOWN type " + str(entry[7])
        self.reading_type = entry[8]  # table 42-1
            # 0: unspecified
            # 1: generic threshold based
            # 0x6f: discrete sensor-specific from table 42-3, sensor offsets
            # all others per table 42-2, generic discrete
        self.numeric_format = (entry[15] & 0b11000000) >> 6
        # the spec technically reserves numeric_format for compact sensor
        # numeric, but common treatment won't break currently
        # 0 - unsigned, 1 - 1s complement, 2 - 2s complement, 3 - ignore number
        self.sensor_rate = sensor_rates[(entry[15] & 0b111000) >> 3]
        self.unit_mod = ""
        if (entry[15] & 0b110) == 0b10:  # unit1 by unit2
            self.unit_mod = "/"
        elif (entry[15] & 0b110) == 0b100:
            # combine the units by multiplying, SI nomenclature is either spac
            # or hyphen, so go with space
            self.unit_mod = " "
        self.percent = ''
        if entry[15] & 1 == 1:
            self.percent = '% '
        self.baseunit = unit_types[entry[16]]
        self.modunit = unit_types[entry[17]]
        self.unit_suffix = self.percent + self.baseunit + self.unit_mod + \
            self.modunit

    def full_decode(self, entry):
        #offsets are table from spec, minus 6
        #TODO: table 43-13, put in constants to interpret entry[3]
        self._common_decode(entry)
        # now must extract the formula data to transform values
        # entry[18 to entry[24].
        # if not linear, must use get sensor reading factors
        # TODO(jbjohnso): the various other values
        self.sensor_name = self.tlv_decode(entry[42], entry[43:])
        self.linearization = entry[18] & 0b1111111
        if self.linearization <= 11:
            # the enumuration of linear sensors goes to 11,
            # static formula parameters are applicable, decode them
            # if 0x70, then the sesor reading will have to get the
            # factors on the fly.
            # the formula could apply if we bother with nominal
            # reading interpretation
            self.decode_formula(entry)

    def decode_sensor_reading(self, reading):
        numeric = None
        output = {
            'name': self.sensor_name,
            }
        print self.sensor_name
        print reading[0]
        if reading[1] & 0b100000:
            output['unavailable'] = 1
            return SensorReading(output)
        if self.numeric_format == 2:
            numeric = twos_complement(reading[0], 8)
        elif self.numeric_format == 1:
            numeric = ones_complement(reading[0], 8)
        elif self.numeric_format == 0:
            numeric = reading[0]
        discrete = True
        if numeric is not None:
            output['value'] = self.decode_value(numeric)
            discrete = False
        upper = 'upper'
        lower = 'lower'
        if self.linearization == 7:
            # if the formula is 1/x, then the intuitive sense of upper and
            # lower are backwards
            upper = 'lower'
            lower = 'upper'
        output['states'] = []
        if not discrete:
            if reading[2] & 0b1:
                output['states'].append(lower + " non-critical threshold")
            if reading[2] & 0b10:
                output['states'].append(lower + " critical threshold")
            if reading[2] & 0b100:
                output['states'].append(lower + " non-recoverable threshold")
            if reading[2] & 0b1000:
                output['states'].append(upper + " non-critical threshold")
            if reading[2] & 0b10000:
                output['states'].append(upper + " critical threshold")
            if reading[2] & 0b100000:
                output['states'].append(upper + " non-recoverable threshold")
            return SensorReading(output)

    def decode_value(self, value):
        # Take the input value and return the more meaningfulk
        if self.linearization == 0x70:  # direct calling code to get factors
            #TODO(jbjohnso): implement get sensor reading factors support for
            #non linear sensor
            raise NotImplementedError("Need to do get sensor reading factors")
        # time to compute the pre-linearization value.
        decoded = (value * self.m + self.b)
        decoded = _round_sigbits(decoded, 8)
        decoded = float(decoded * (10 ** self.resultexponent))
        if self.linearization == 0:
            return decoded
        elif self.linearization == 1:
            return math.log(decoded)
        elif self.linearization == 2:
            return math.log(decoded, 10)
        elif self.linearization == 3:
            return math.log(decoded, 2)
        elif self.linearization == 4:
            return math.exp(decoded)
        elif self.linearization == 5:
            return 10 ** decoded
        elif self.linearization == 6:
            return 2 ** decoded
        elif self.linearization == 7:
            return 1 / decoded
        elif self.linearization == 8:
            return decoded ** 2
        elif self.linearization == 9:
            return decoded ** 3
        elif self.linearization == 10:
            return math.sqrt(decoded)
        elif self.linearization == 11:
            return decoded ** (1.0/3)
        else:
            raise NotImplementedError

    def decode_formula(self, entry):
        self.m = \
            twos_complement(entry[19] + ((entry[20] & 0b11000000) << 2), 10)
        self.tolerance = entry[20] & 0b111111
        self.b = \
            twos_complement(entry[21] + ((entry[22] & 0b11000000) << 2), 10)
        self.accuracy = (entry[22] & 0b111111) + \
            (entry[23] & 0b11110000) << 2
        self.accuracyexp = (entry[23] & 0b1100) >> 2
        self.direction = entry[23] & 0b11
            #0 = n/a, 1 = input, 2 = output
        self.resultexponent = twos_complement((entry[24] & 0b11110000) >> 4, 4)
        bexponent = twos_complement(entry[24] & 0b1111, 4)
        # might as well do the math to 'b' now rather than wait for later
        self.b = self.b * (10**bexponent)

    def tlv_decode(self, tlv, data):
        # Per IPMI 'type/length byte format
        type = (tlv & 0b11000000) >> 6
        if not len(data):
            return ""
        if type == 0:  # Unicode per 43.15 in ipmi 2.0 spec
            # the spec is not specific about encoding, assuming utf8
            return unicode(struct.pack("%dB" % len(data), *data), "utf_8")
        elif type == 1:  # BCD '+'
            tmpl = "%02X" * len(data)
            tstr = tmpl % tuple(data)
            tstr = tstr.replace("A", " ").replace("B", "-").replace("C", ".")
            return tstr.replace("D", ":").replace("E", ",").replace("F", "_")
        elif type == 2:  # 6 bit ascii, start at 0x20 and stop when out of bits
            # the ordering is very peculiar and is best understood from
            # IPMI SPEC "6-bit packed ascii example
            tstr = ""
            while len(data) >= 3:  # the packing only works with 3 byte chunks
                tstr += chr((data[0] & 0b111111) + 0x20)
                tstr += chr(((data[1] & 0b1111) << 2) +
                            (data[0] >> 6) + 0x20)
                tstr += chr(((data[2] & 0b11) << 4) +
                            (data[1] >> 4) + 0x20)
                tstr += chr((data[2] >> 2) + 0x20)
            return tstr
        elif type == 3:  # ACSII+LATIN1
            return struct.pack("%dB" % len(data), *data)


class SDR(object):
    """Examine the state of sensors managed by a BMC

    Presents the data from sensor read commands as directed by the SDR in a
    reasonable format.

    """
    def __init__(self, ipmicmd):
        self.ipmicmd = ipmicmd
        self.sensors = {}
        self.fru = {}
        self.read_info()

    def read_info(self):
        #first, we want to know the device id
        rsp = self.ipmicmd.raw_command(netfn=6, command=1)
        self.device_id = rsp['data'][0]
        self.device_rev = rsp['data'][1] & 0b111
        # Going to ignore device available until get sdr command
        # since that provides usefully distinct state and this does not
        self.fw_major = rsp['data'][2] & 0b1111111
        self.fw_minor = "%02X" % rsp['data'][3]  # BCD encoding, oddly enough
        if rsp['data'][1] & 0b10000000:
            # For lack of any system with 'device sdrs', raise an
            # exception when they are encountered for now, implement or
            # ignore later
            raise NotImplementedError
        self.ipmiversion = rsp['data'][4]  # 51h = 1.5, 02h = 2.0
        self.mfg_id = rsp['data'][8] << 16 + rsp['data'][7] << 8 + \
            rsp['data'][6]
        self.prod_id = rsp['data'][10] << 8 + rsp['data'][9]
        if len(rsp['data']) > 11:
            self.aux_fw = self.decode_aux(rsp['data'][11:15])
        self.get_sdr()

    def get_sdr(self):
        rsp = self.ipmicmd.raw_command(netfn=0x0a, command=0x20)
        if (rsp['data'][0] != 0x51):
            # we only understand SDR version 51h, the only version defined
            # at time of this writing
            raise NotImplementedError
        #NOTE(jbjohnso): we actually don't need to care about 'numrecords'
        # since FFFF marks the end explicitly
        #numrecords = (rsp['data'][2] << 8) + rsp['data'][1]
        #NOTE(jbjohnso): don't care about 'free space' at the moment
        #NOTE(jbjohnso): most recent timstamp data for add and erase could be
        # handy to detect cache staleness, but for now will assume invariant
        # over life of session
        #NOTE(jbjohnso): not looking to support the various options in op
        # support, ignore those for now, reservation if some BMCs can't read
        # full SDR in one slurp
        recid = 0
        rsvid = 0  # partial 'get sdr' will require this
        offset = 0
        size = 0xff
        while recid != 0xffff:  # per 33.12 Get SDR command, 0xffff marks end
            rqdata = [rsvid & 0xff, rsvid >> 8,
                      recid & 0xff, recid >> 8,
                      offset, size]
            rsp = self.ipmicmd.raw_command(netfn=0x0a, command=0x23,
                                           data=rqdata)
            newrecid = (rsp['data'][1] << 8) + rsp['data'][0]
            self.add_sdr(rsp['data'][2:])
            if newrecid == recid:
                raise exc.BmcErrorException("Incorrect SDR record id from BMC")
            recid = newrecid

    def get_sensor_numbers(self):
        return self.sensors.iterkeys()

    def add_sdr(self, sdrbytes):
        newent = SDREntry(sdrbytes)
        if newent.sdrtype == TYPE_SENSOR:
            id = newent.sensor_number
            if id in self.sensors:
                raise exc.BmcErrorException("Duplicate sensor number " + id)
            self.sensors[id] = newent
        elif newent.sdrtype == TYPE_FRU:
            id = newent.fru_number
            if id in self.fru:
                raise exc.BmcErrorException("Duplicate FRU identifier " + id)
            self.fru[id] = newent

    def decode_aux(self, auxdata):
        # This is where manufacturers can add their own
        # decode information
        return "".join(hex(x) for x in auxdata)

if __name__ == "__main__":  # test code
    import sys
    import os
    password = os.environ['IPMIPASSWORD']
    bmc = sys.argv[1]
    user = sys.argv[2]
    ipmicmd = ipmicmd.Command(bmc=bmc, userid=user, password=password)
    sdr = SDR(ipmicmd)
    for number in sdr.get_sensor_numbers():
        rsp = ipmicmd.raw_command(command=0x2d, netfn=4, data=(number,))
        if 'error' in rsp:
            continue
        print repr(sdr.sensors[number].decode_sensor_reading(rsp['data']))
