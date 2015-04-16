# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf8

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

# This file handles parsing of fru format records as presented by IPMI
# devices.  This format is documented in the 'Platform Management FRU
# Information Storage Definition (Document Revision 1.2)

import pyghmi.exceptions as iexc
import struct
import time

fruepoch = time.mktime(time.strptime('1/1/1996', "%m/%d/%Y"))

# This is from SMBIOS specification Table 16
enclosure_types = {
    1: 'Other',
    2: 'Unknown',
    3: 'Desktop',
    4: 'Low Profile Desktop',
    5: 'Pizza Box',
    6: 'Mini Tower',
    7: 'Tower',
    8: 'Portable',
    9: 'Laptop',
    0xa: 'Notebook',
    0xb: 'Hand Held',
    0xc: 'Docking Station',
    0xd: 'All in One',
    0xe: 'Sub Notebook',
    0xf: 'Space-saving',
    0x10: 'Lunch Box',
    0x11: 'Main Server Chassis',
    0x12: 'Expansion Chassis',
    0x13: 'SubChassis',
    0x14: 'Bus Expansion Chassis',
    0x15: 'Peripheral Chassis',
    0x16: 'RAID Chassis',
    0x17: 'Rack Mount Chassis',
    0x18: 'Sealed-case PC',
    0x19: 'Multi-system Chassis',
    0x1a: 'Compact PCI',
    0x1b: 'Advanced TCA',
    0x1c: 'Blade',
    0x1d: 'Blade Enclosure',
}


def unpack6bitascii(inputdata):
    # This is a text encoding scheme that seems unique
    # to IPMI FRU.  It seems to be relatively rare in practice
    result = ''
    while len(inputdata) > 0:
        currchunk = inputdata[:3]
        del inputdata[:3]
        currchar = currchunk[0] & 0b111111
        result += chr(0x20 + currchar)
        currchar = (currchunk[0] & 0b11000000) >> 6
        currchar |= (currchunk[1] & 0b1111) << 2
        result += chr(0x20 + currchar)
        currchar = (currchunk[1] & 0b1111000) >> 4
        currchar |= (currchunk[2] & 0b11) << 4
        result += chr(0x20 + currchar)
        currchar = (currchunk[2] & 0b11111100) >> 2
        result += chr(0x20 + currchar)
    return result


def decode_fru_date(datebytes):
    # Returns ISO
    datebytes.append(0)
    minutesfromepoch = struct.unpack('<I', struct.pack('4B', *datebytes))[0]
    if minutesfromepoch == 0:
        return None
    return time.strftime('%Y-%m-%dT%H:%M',
                         time.gmtime((minutesfromepoch * 60) + fruepoch))


class FRU(object):
    """An object representing structure

    FRU (Field Replaceable Unit) is the usual format for inventory in IPMI
    devices.  This covers most standards compliant inventory data
    as well as presenting less well defined fields in a structured way.

    :param rawdata: A binary string/bytearray of raw data from BMC
    """

    def __init__(self, rawdata):
        self.databytes = bytearray(rawdata)
        if self.databytes[0] != 1:
            raise iexc.BmcErrorException("Invalid/Unsupported FRU format")
        # Ignore the internal use even if present.
        self._parse_chassis()
        self._parse_board()
        self._parse_prod()
        # TODO(jjohnson2): Multi Record area

    def _decode_tlv(self, offset, lang=0):
        currtlv = self.databytes[offset]
        currlen = currtlv & 0b111111
        currtype = (currtlv & 0b11000000) >> 6
        retinfo = self.databytes[offset + 1:offset + currlen]
        newoffset = offset + currlen + 1
        if currlen == 0:
            return None, newoffset
        if currtype == 0:
            # return it as a bytearray, not much to be done for it
            return retinfo, newoffset
        elif currtype == 3:  # text string
            if lang == 0:
                retinfo = retinfo.decode('utf-8')
            else:
                retinfo = retinfo.decode('utf-16le')
            retinfo = retinfo.replace('\x00', '')
            return retinfo, newoffset
        elif currtype == 1:  # BCD 'plus'
            retdata = ''
            for byte in retinfo:
                byte = hex(byte).replace('0x', '').replace('a', ' ').replace(
                    'b', '-').replace('c', '.')
                retdata += byte
            return retdata, newoffset
        elif currtype == 2:  # 6-bit ascii
            retinfo = unpack6bitascii(retinfo)
            return retinfo, newoffset

    def _parse_chassis(self):
        offset = 8 * self.databytes[2]
        if offset == 0:
            return
        if self.databytes[offset] & 0b1111 != 1:
            raise iexc.BmcErrorException("Invallid/Unsupported chassis area")
        # ignore length field, just process the data
        self.chassis_type = enclosure_types[self.databytes[offset + 2]]
        self.chassis_part_number, offset = self._decode_tlv(offset + 3)
        self.chassis_serial, offset = self._decode_tlv(offset)
        self.chassis_extra = []
        while self.databytes[offset] != 0xc1:
            fielddata, offset = self._decode_tlv(offset)
            self.chassis_extra.append(fielddata)

    def _parse_board(self):
        offset = 8 * self.databytes[3]
        if offset == 0:
            return
        if self.databytes[offset] & 0b1111 != 1:
            raise iexc.BmcErrorException("Invalid/Unsupported board info area")
        language = self.databytes[offset + 2]
        self.board_mfg_date = decode_fru_date(
            self.databytes[offset + 3:offset + 6])
        self.board_manufacturer, offset = self._decode_tlv(offset + 6)
        self.board_product, offset = self._decode_tlv(offset, language)
        self.board_serial, offset = self._decode_tlv(offset, language)
        self.board_model, offset = self._decode_tlv(offset, language)
        _, offset = self._decode_tlv(offset, language)  # decode but discard
        self.board_extra = []
        while self.databytes[offset] != 0xc1:
            fielddata, offset = self._decode_tlv(offset, language)
            self.board_extra.append(fielddata)

    def _parse_prod(self):
        offset = 8 * self.databytes[4]
        if offset == 0:
            return
        language = self.databytes[offset + 2]
        self.product_manufacturer, offset = self._decode_tlv(offset + 3,
                                                             language)
        self.product_name, offset = self._decode_tlv(offset, language)
        self.product_model, offset = self._decode_tlv(offset, language)
        self.product_version, offset = self._decode_tlv(offset, language)
        self.product_serial, offset = self._decode_tlv(offset, language)
        self.product_asset, offset = self._decode_tlv(offset, language)
        _, offset = self._decode_tlv(offset, language)
        self.product_extra = []
        while self.databytes[offset] != 0xc1:
            fielddata, offset = self._decode_tlv(offset, language)
            self.product_extra.append(fielddata)

    def __repr__(self):
        retdata = 'Chassis data\n'
        retdata += '   Type: ' + repr(self.chassis_type) + '\n'
        retdata += '   Part Number: ' + repr(self.chassis_part_number) + '\n'
        retdata += '   Serial Number: ' + repr(self.chassis_serial) + '\n'
        retdata += '   Extra: ' + repr(self.chassis_extra) + '\n'
        retdata += 'Board data\n'
        retdata += '  Manufacturer: ' + repr(self.board_manufacturer) + '\n'
        retdata += '   Date: ' + repr(self.board_mfg_date) + '\n'
        retdata += '   Product' + repr(self.board_product) + '\n'
        retdata += '   Serial: ' + repr(self.board_serial) + '\n'
        retdata += '   Model: ' + repr(self.board_model) + '\n'
        retdata += '   Extra: ' + repr(self.board_extra) + '\n'
        retdata += 'Product data\n'
        retdata += '  Manufacturer: ' + repr(self.product_manufacturer) + '\n'
        retdata += '  Name: ' + repr(self.product_name) + '\n'
        retdata += '  Model: ' + repr(self.product_model) + '\n'
        retdata += '  Version: ' + repr(self.product_version) + '\n'
        retdata += '  Serial: ' + repr(self.product_serial) + '\n'
        retdata += '  Asset: ' + repr(self.product_asset) + '\n'
        retdata += '  Extra: ' + repr(self.product_extra) + '\n'
        return retdata
