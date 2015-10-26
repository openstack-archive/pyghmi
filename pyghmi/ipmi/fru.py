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
import pyghmi.ipmi.private.spd as spd
import struct
import time

fruepoch = 820454400  # 1/1/1996, 0:00

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
        currchar = (currchunk[1] & 0b11110000) >> 4
        currchar |= (currchunk[2] & 0b11) << 4
        result += chr(0x20 + currchar)
        currchar = (currchunk[2] & 0b11111100) >> 2
        result += chr(0x20 + currchar)
    return result


def decode_fru_date(datebytes):
    # Returns ISO
    datebytes.append(0)
    minutesfromepoch = struct.unpack('<I', struct.pack('4B', *datebytes))[0]
    # Some data in the field has had some data less than 800
    # At this juncture, it's far more likely for this noise
    # to be incorrect than anything in particular
    if minutesfromepoch < 800:
        return None
    return time.strftime('%Y-%m-%dT%H:%M',
                         time.gmtime((minutesfromepoch * 60) + fruepoch))


class FRU(object):
    """An object representing structure

    FRU (Field Replaceable Unit) is the usual format for inventory in IPMI
    devices.  This covers most standards compliant inventory data
    as well as presenting less well defined fields in a structured way.

    :param rawdata: A binary string/bytearray of raw data from BMC or dump
    :param ipmicmd: An ipmi command object to fetch data live
    :param fruid: The identifier number of the FRU
    :param sdr: The sdr locator entry to help clarify how to parse data
    """

    def __init__(self, rawdata=None, ipmicmd=None, fruid=0, sdr=None):
        self.rawfru = rawdata
        self.databytes = None
        self.info = None
        self.sdr = sdr
        if self.rawfru is not None:
            self.parsedata()
        elif ipmicmd is not None:
            self.ipmicmd = ipmicmd
            # Use the ipmicmd to fetch the data
            try:
                self.fetch_fru(fruid)
            except iexc.IpmiException as ie:
                if ie.ipmicode in (203, 129):
                    return
                raise
            self.parsedata()
        else:
            raise TypeError('Either rawdata or ipmicmd must be specified')

    def fetch_fru(self, fruid):
        response = self.ipmicmd.raw_command(
            netfn=0xa, command=0x10, data=[fruid])
        if 'error' in response:
            raise iexc.IpmiException(response['error'], code=response['code'])
        frusize = response['data'][0] | (response['data'][1] << 8)
        # In our case, we don't need to think too hard about whether
        # the FRU is word or byte, we just process what we get back in the
        # payload
        chunksize = 240
        # Selected as it is accomodated by most tested things
        # and many tested things broke after going much
        # bigger
        if chunksize > frusize:
            chunksize = frusize
        offset = 0
        self.rawfru = bytearray([])
        while chunksize:
            response = self.ipmicmd.raw_command(
                netfn=0xa, command=0x11, data=[fruid, offset & 0xff,
                                               offset >> 8, chunksize])
            if response['code'] in (201, 202):
                # if it was too big, back off and try smaller
                # Try just over half to mitigate the chance of
                # one request becoming three rather than just two
                if chunksize == 3:
                    raise iexc.IpmiException(response['error'])
                chunksize //= 2
                chunksize += 2
                continue
            elif 'error' in response:
                raise iexc.IpmiException(response['error'], response['code'])
            self.rawfru.extend(response['data'][1:])
            offset += response['data'][0]
            if response['data'][0] == 0:
                break
            if offset + chunksize > frusize:
                chunksize = frusize - offset

    def parsedata(self):
        self.info = {}
        rawdata = self.rawfru
        self.databytes = bytearray(rawdata)
        if self.sdr is not None:
            frutype = self.sdr.fru_type_and_modifier >> 8
            frusubtype = self.sdr.fru_type_and_modifier & 0xff
            if frutype > 0x10 or frutype < 0x8 or frusubtype not in (0, 1, 2):
                return
                #TODO(jjohnson2): strict mode to detect pyghmi and BMC
                #gaps
                # raise iexc.PyghmiException(
                #     'Unsupported FRU device: {0:x}h, {1:x}h'.format(frutype,
                #                                                    frusubtype
                #                                                    ))
            elif frusubtype == 1:
                self.myspd = spd.SPD(self.databytes)
                self.info = self.myspd.info
                return
        if self.databytes[0] != 1:
            return
            #TODO(jjohnson2): strict mode to flag potential BMC errors
            # raise iexc.BmcErrorException("Invalid/Unsupported FRU format")
        # Ignore the internal use even if present.
        self._parse_chassis()
        self._parse_board()
        self._parse_prod()
        # TODO(jjohnson2): Multi Record area

    def _decode_tlv(self, offset, lang=0):
        currtlv = self.databytes[offset]
        currlen = currtlv & 0b111111
        currtype = (currtlv & 0b11000000) >> 6
        retinfo = self.databytes[offset + 1:offset + currlen + 1]
        newoffset = offset + currlen + 1
        if currlen == 0:
            return None, newoffset
        if currtype == 0:
            # return it as a bytearray, not much to be done for it
            return retinfo, newoffset
        elif currtype == 3:  # text string
            # Sometimes BMCs have FRU data with 0xff termination
            # contrary to spec, but can be tolerated
            # also in case something null terminates, handle that too
            # strictly speaking, \xff should be a y with diaeresis, but
            # erring on the side of that not being very relevant in practice
            # to fru info, particularly the last values
            retinfo = retinfo.rstrip('\xff\x00 ')
            if lang in (0, 25):
                try:
                    retinfo = retinfo.decode('iso-8859-1')
                except UnicodeDecodeError:
                    pass
            else:
                try:
                    retinfo = retinfo.decode('utf-16le')
                except UnicodeDecodeError:
                    pass
            # Some things lie about being text.  Do the best we can by
            # removing trailing spaces and nulls like makes sense for text
            # and rely on vendors to workaround deviations in their OEM
            # module
            retinfo = retinfo.rstrip('\x00 ')
            return retinfo, newoffset
        elif currtype == 1:  # BCD 'plus'
            retdata = ''
            for byte in retinfo:
                byte = hex(byte).replace('0x', '').replace('a', ' ').replace(
                    'b', '-').replace('c', '.')
                retdata += byte
            retdata = retdata.strip()
            return retdata, newoffset
        elif currtype == 2:  # 6-bit ascii
            retinfo = unpack6bitascii(retinfo).strip()
            return retinfo, newoffset

    def _parse_chassis(self):
        offset = 8 * self.databytes[2]
        if offset == 0:
            return
        if self.databytes[offset] & 0b1111 != 1:
            raise iexc.BmcErrorException("Invallid/Unsupported chassis area")
        inf = self.info
        # ignore length field, just process the data
        inf['Chassis type'] = enclosure_types[self.databytes[offset + 2]]
        inf['Chassis part number'], offset = self._decode_tlv(offset + 3)
        inf['Chassis serial number'], offset = self._decode_tlv(offset)
        inf['chassis_extra'] = []
        self.extract_extra(inf['chassis_extra'], offset)

    def extract_extra(self, target, offset, language=0):
        try:
            while self.databytes[offset] != 0xc1:
                fielddata, offset = self._decode_tlv(offset, language)
                target.append(fielddata)
        except IndexError:
            # If we overrun the end due to malformed FRU,
            # return at least what decoded right
            return

    def _parse_board(self):
        offset = 8 * self.databytes[3]
        if offset == 0:
            return
        if self.databytes[offset] & 0b1111 != 1:
            raise iexc.BmcErrorException("Invalid/Unsupported board info area")
        inf = self.info
        language = self.databytes[offset + 2]
        inf['Board manufacture date'] = decode_fru_date(
            self.databytes[offset + 3:offset + 6])
        inf['Board manufacturer'], offset = self._decode_tlv(offset + 6)
        inf['Board product name'], offset = self._decode_tlv(offset, language)
        inf['Board serial number'], offset = self._decode_tlv(offset, language)
        inf['Board model'], offset = self._decode_tlv(offset, language)
        _, offset = self._decode_tlv(offset, language)  # decode but discard
        inf['board_extra'] = []
        self.extract_extra(inf['board_extra'], offset, language)

    def _parse_prod(self):
        offset = 8 * self.databytes[4]
        if offset == 0:
            return
        inf = self.info
        language = self.databytes[offset + 2]
        inf['Manufacturer'], offset = self._decode_tlv(offset + 3,
                                                       language)
        inf['Product name'], offset = self._decode_tlv(offset, language)
        inf['Model'], offset = self._decode_tlv(offset, language)
        inf['Hardware Version'], offset = self._decode_tlv(offset, language)
        inf['Serial Number'], offset = self._decode_tlv(offset, language)
        inf['Asset Number'], offset = self._decode_tlv(offset, language)
        _, offset = self._decode_tlv(offset, language)
        inf['product_extra'] = []
        self.extract_extra(inf['product_extra'], offset, language)

    def __repr__(self):
        return repr(self.info)
        # retdata = 'Chassis data\n'
        # retdata += '   Type: ' + repr(self.chassis_type) + '\n'
        # retdata += '   Part Number: ' + repr(self.chassis_part_number) + '\n'
        # retdata += '   Serial Number: ' + repr(self.chassis_serial) + '\n'
        # retdata += '   Extra: ' + repr(self.chassis_extra) + '\n'
        # retdata += 'Board data\n'
        # retdata += '  Manufacturer: ' + repr(self.board_manufacturer) + '\n'
        # retdata += '   Date: ' + repr(self.board_mfg_date) + '\n'
        # retdata += '   Product' + repr(self.board_product) + '\n'
        # retdata += '   Serial: ' + repr(self.board_serial) + '\n'
        # retdata += '   Model: ' + repr(self.board_model) + '\n'
        # retdata += '   Extra: ' + repr(self.board_extra) + '\n'
        # retdata += 'Product data\n'
        # retdata += '  Manufacturer: ' + repr(self.product_manufacturer)+'\n'
        # retdata += '  Name: ' + repr(self.product_name) + '\n'
        # retdata += '  Model: ' + repr(self.product_model) + '\n'
        # retdata += '  Version: ' + repr(self.product_version) + '\n'
        # retdata += '  Serial: ' + repr(self.product_serial) + '\n'
        # retdata += '  Asset: ' + repr(self.product_asset) + '\n'
        # retdata += '  Extra: ' + repr(self.product_extra) + '\n'
        # return retdata
