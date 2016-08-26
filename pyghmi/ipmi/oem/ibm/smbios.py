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

import os
import random
import struct
import traceback

import pyghmi.exceptions as pygexc

oem_smbios_cmds = {
    "query": {
        "netfn": 0x2e,
        "command": 0x90,
        "data": [0x4d, 0x4f, 0x00, 0x06, 0x73, 0x6d, 0x62, 0x69, 0x6f, 0x73,
                 0x2d, 0x74, 0x61, 0x62, 0x6c, 0x65]
    },
    "open": {
        "netfn": 0x2e,
        "command": 0x90,
        "data": [0x4d, 0x4f, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x73, 0x6d, 0x62, 0x69, 0x6f, 0x73, 0x2d, 0x74,
                 0x61, 0x62, 0x6c, 0x65]
    },
    "read": {
        "netfn": 0x2e,
        "command": 0x90,
        "data": [0x4d, 0x4f, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0xe0, 0x00]
    },
    "close": {
        "netfn": 0x2e,
        "command": 0x90,
        "data": [0x4d, 0x4f, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00]
    }
}

processor_family = {
    # definition of Intel processor family
    '0B': 'Intel(R) Pentium(R) processor',
    '0C': 'Intel(R) Pentium(R) pro processor',
    '0D': 'Intel(R) Pentium(R) II processor',
    '0F': 'Intel(R) Celeron(R) processor',
    '10': 'Intel(R) Pentium(R) II Xeon(R) processor',
    '11': 'Intel(R) Pentium(R) III processor',
    '14': 'Intel(R) Celeron(R) M processor',
    'B0': 'Intel(R) Pentium(R) III Xeon(R) processor',
    'B2': 'Intel(R) Pentium(R) 4 processor',
    'BA': 'Intel(R) Celeron(R) D processor',
    'CD': 'Intel(R) Core(TM) i5 processor',
    'CE': 'Intel(R) Core(TM) i3 processor',
    'A1': 'Quad-Core Intel(R) Xeon(R) processor 3200 Series',
    'A2': 'Dual-Core Intel(R) Xeon(R) processor 3000 Series',
    'A3': 'Quad-Core Intel(R) Xeon(R) processor 5300 Series',
    'A4': 'Dual-Core Intel(R) Xeon(R) processor 5100 Series',
    'A5': 'Dual-Core Intel(R) Xeon(R) processor 5000 Series',
    'A6': 'Dual-Core Intel(R) Xeon(R) processor LV',
    'A7': 'Dual-Core Intel(R) Xeon(R) processor ULV',
    'A8': 'Dual-Core Intel(R) Xeon(R) processor 7100 Series',
    'A9': 'Quad-Core Intel(R) Xeon(R) processor 5400 Series',
    'AA': 'Quad-Core Intel(R) Xeon(R) processor',
    'AB': 'Dual-Core Intel(R) Xeon(R) processor 5200 Series',
    'AC': 'Dual-Core Intel(R) Xeon(R) processor 7200 Series',
    'AD': 'Quad-Core Intel(R) Xeon(R) processor 7300 Series',
    'AE': 'Quad-Core Intel(R) Xeon(R) processor 7400 Series',
    'AF': 'Multi-Core Intel(R) Xeon(R) processor 7400 Series',
    'B3': 'Intel(R) Xeon(R) processor',
    'B5': 'Intel(R) Xeon(R) processor MP',
    'DD': 'Dual-Core Intel(R) Xeon(R) processor 7xxx Series',
    'DE': 'Quad-Core Intel(R) Xeon(R) processor 7xxx Series',
    'DF': 'Multi-Core Intel(R) Xeon(R) processor 7xxx Series',
    'E0': 'Multi-Core Intel(R) Xeon(R) processor 3400 Series',
    'D6': 'Multi-Core Intel(R) Xeon(R) processor',
    'D7': 'Dual-Core Intel(R) Xeon(R) processor 3xxx Series',
    'D8': 'Quad-Core Intel(R) Xeon(R) processor 3xxx Series',
    'DA': 'Dual-Core Intel(R) Xeon(R) processor 5xxx Series',
    'DB': 'Quad-Core Intel(R) Xeon(R) processor 5xxx Series'
}

processor_status = {
    # definition of processor status
    '0': 'Unknown',
    '1': 'Enabled',
    '2': 'Disabled by User through BIOS Setup',
    '3': 'Disabled By BIOS (POSTError)',
    '4': 'CPU is Idle, waiting to be enabled.',
    '7': 'Other'
}


def get_smbios_info(ipmicmd):
    """get the smbios info from the specific server
   :raises: IpmiException on an error.
   :returns: raw data of smbios table
    """
    oem_smbios_info = []

    # send ipmi command to query the size of smbios table
    read_command = oem_smbios_cmds["query"]
    try:
        rsp = ipmicmd.xraw_command(**read_command)
    except pygexc.IpmiException:
        print traceback.print_exc()
        return None

    # extract the smbios table size from response
    c1 = ord(rsp["data"][3])
    c2 = ord(rsp["data"][4]) << 8
    c3 = ord(rsp["data"][5]) << 16
    c4 = ord(rsp["data"][6]) << 24
    smbios_table_size = c1 | c2 | c3 | c4

    # open the smbios table
    open_command = oem_smbios_cmds["open"]
    data_size = struct.unpack('4B', rsp["data"][3:7])
    open_command["data"][6:10] = data_size

    try:
        rsp = ipmicmd.xraw_command(**open_command)
    except pygexc.IpmiException:
        print traceback.print_exc()
        return None

    # extract the data handle from the response
    data_handle = struct.unpack('4B', rsp["data"][3:7])

    # read the smbios table
    bytes_to_read = 0xe0
    bytes_count = 0

    while bytes_count < smbios_table_size:
        read_command = oem_smbios_cmds["read"]
        # set the data handle, offset and byte to read for ipmi command
        read_command["data"][4:8] = data_handle
        read_command["data"][8] = bytes_count & 0xff
        read_command["data"][9] = bytes_count >> 8 & 0xff
        read_command["data"][10] = bytes_count >> 16 & 0xff
        read_command["data"][11] = bytes_count >> 24 & 0xff
        read_command["data"][12] = bytes_to_read & 0xff
        read_command["data"][13] = bytes_to_read >> 8 & 0xff

        try:
            rsp = ipmicmd.xraw_command(**read_command)
        except pygexc.IpmiException:
            print traceback.print_exc()
            return None

        bytes_read = ord(rsp["data"][4]) << 8 | ord(rsp["data"][3])
        bytes_count += bytes_read
        if (smbios_table_size - bytes_count) < 0xe0:
            bytes_to_read = smbios_table_size - bytes_count

        oem_smbios_info.extend(rsp["data"][5:])

    # close the smbios table
    close_command = oem_smbios_cmds["close"]
    close_command["data"][4:8] = data_handle

    try:
        rsp = ipmicmd.xraw_command(**close_command)
    except pygexc.IpmiException:
        print traceback.print_exc()

    return oem_smbios_info


def parse_smbios_info(raw):
    """parse the smbios info from the specific server
   :param: raw: raw data of the smbios info
   :raises: IpmiException on an error.
   :returns: dictionary of smbios table
    """

    # write the raw data to the temporary file for processing
    num = random.randint(1, 65535)
    filename = 'smbios' + str(num)
    write_file = open(filename, 'wb')
    for item in raw:
        write_file.write(item)
    write_file.close()

    result = []

    try:
        with open(filename, 'rb') as input_file:
            # pass the SMBIOS entry point structure
            input_file.read(22)
            size_of_table = struct.unpack('<H', input_file.read(2))[0] + 31
            input_file.read(7)
            # read the first byte of the table
            b = input_file.read(1)
            prv = -1
            while b and input_file.tell() < size_of_table:
                byte = ord(b)
                # read the pattern for type 0 - BIOS
                if prv == 0 and byte == 24:
                    temp = type0(input_file)
                    if temp:
                        result.append(temp)
                # read the pattern for type 4 - Processor
                if prv == 4 and byte == 42:
                    temp = type4(input_file)
                    if temp:
                        result.append(temp)
                # read the OEM strings
                if prv == 11 and byte == 5:
                    temp = type11(input_file)
                    if temp:
                        result.append(temp)
                prv = byte
                b = input_file.read(1)
        os.remove(filename)
    except Exception, e:
        print(e)
        return None

    return result


def type0(input_file):
    """parse the smbios info to get type 0 - BIOS
   :param: input_file: the file object for reading smbios info
   :raises: IndexError on an error.
   :returns: BIOS info
    """
    try:
        vendor, bios_version, bios_rls_date = '', '', ''
        input_file.read(2)
        vendor_idx = ord(input_file.read(1))
        bios_version_idx = ord(input_file.read(1))
        input_file.read(2)
        bios_rls_date_idx = ord(input_file.read(1))
        input_file.read(15)
        # get the string array for type 0
        str_ary = get_str_array(input_file)
        # get the string from array
        vendor = str_ary[vendor_idx - 1]
        bios_version = str_ary[bios_version_idx - 1][2:-2]
        bios_rls_date = str_ary[bios_rls_date_idx - 1]
        return {
            "Type": "BIOS",
            "Vendor": vendor,
            "Version": bios_version,
            "Release Date": bios_rls_date
        }
    except IndexError:
        return None


def type1(input_file):
    """parse the smbios info to get type 1 - System
   :param: input_file: the file object for reading smbios info
   :raises: IndexError on an error.
   :returns: System info
    """
    try:
        manufacturer, product_name, serial_number, uuid = '', '', '', ''
        input_file.read(2)
        manufacturer_idx = ord(input_file.read(1))
        product_name_idx = ord(input_file.read(1))
        input_file.read(1)
        serial_number_idx = ord(input_file.read(1))
        # read the uuid of system
        uuid_ary = []
        for i in xrange(16):
            b = str(hex(ord(input_file.read(1))))[2:].upper()
            if len(b) == 1:
                b = "0{0}".format(b)
            uuid_ary.append(b)
        input_file.read(3)
        # get the string array for type 1
        str_ary = get_str_array(input_file)
        # get the string from array
        manufacturer = str_ary[manufacturer_idx - 1]
        product_name = str_ary[product_name_idx - 1]
        serial_number = str_ary[serial_number_idx - 1]
        uuid = uuid_ary[3]
        uuid += uuid_ary[2]
        uuid += uuid_ary[1]
        uuid += uuid_ary[0]
        uuid += uuid_ary[5]
        uuid += uuid_ary[4]
        uuid += uuid_ary[7]
        uuid += uuid_ary[6]
        uuid += uuid_ary[8]
        uuid += uuid_ary[9]
        uuid += uuid_ary[10]
        uuid += uuid_ary[11]
        uuid += uuid_ary[12]
        uuid += uuid_ary[13]
        uuid += uuid_ary[14]
        uuid += uuid_ary[15]
        return {
            "Type": "System",
            "Manufacturer": manufacturer,
            "Product Name": product_name,
            "Serial Number": serial_number,
            "UUID": uuid
        }
    except IndexError:
        return None


def type4(input_file):
    """parse the smbios info to get type 4 - Processor
   :param: input_file: the file object for reading smbios info
   :raises: Exception on an error.
   :returns: dict - Processor info
    """
    try:
        socket_designation = ''
        processor_family_name = ''
        processor_manufacturer = ''
        processor_version = ''
        speed = ''
        status = ''
        serial_number = ''
        core_count = 0
        core_enabled = 0
        thread_count = 0
        input_file.read(2)
        socket_designation_idx = ord(input_file.read(1))
        input_file.read(1)
        index = str(hex(ord(input_file.read(1))))[2:].upper().rjust(2, '0')
        if processor_family.get(index):
            processor_family_name = processor_family[index]
        else:
            processor_family_name = processor_family['B3']

        processor_manufacturer_idx = ord(input_file.read(1))
        input_file.read(8)
        processor_version_idx = ord(input_file.read(1))
        input_file.read(5)
        # read the current speed
        a = ord(input_file.read(1))
        b = ord(input_file.read(1))
        cs = a + b * 256
        status_description = str(hex(ord(input_file.read(1))))[2:].upper()
        if len(status_description) == 1:
            status_description = "0{0}".format(status_description)
        if status_description[0] == '0':
            status += 'Unpopulated'
        else:
            status += 'Populated'

        status += '; ' + processor_status[status_description[1]]
        input_file.read(7)
        serial_number_idx = ord(input_file.read(1))
        input_file.read(2)
        core_count = ord(input_file.read(1))
        core_enabled = ord(input_file.read(1))
        thread_count = ord(input_file.read(1))
        input_file.read(4)
        # get the string array for type 4
        str_ary = get_str_array(input_file)
        # get the string from array
        socket_designation = str_ary[socket_designation_idx - 1]
        processor_manufacturer = str_ary[processor_manufacturer_idx - 1]
        processor_version = str_ary[processor_version_idx - 1]
        speed = str(cs) + " MHz"
        if serial_number_idx != 0:
            serial_number = str_ary[serial_number_idx - 1]
        return {
            "Type": "CPU",
            "Socket": socket_designation,
            "Manufacturer": processor_manufacturer,
            "Family": processor_family_name,
            "Model": processor_version,
            "Maximum Frequency": speed,
            "Status": status,
            "Serial Number": serial_number,
            "Cores": core_count,
            "Core Enabled": core_enabled,
            "Threads": thread_count
        }
    except Exception, e:
        print(e)
        return None


def type11(input_file):
    str_array = []
    try:
        input_file.read(3)
        str_array.extend(get_str_array(input_file))
        return {
            "Type": "OEM Strings",
            "OEM Strings": str_array
        }
    except IndexError:
        return None


def get_str_array(input_file):
    """read the strings in the smbios info
    """
    str_array = []
    b = input_file.read(1)
    while ord(b):
        temp = ''
        while ord(b):
            temp += b
            b = input_file.read(1)
        str_array.append(temp)
        b = input_file.read(1)
    return str_array
