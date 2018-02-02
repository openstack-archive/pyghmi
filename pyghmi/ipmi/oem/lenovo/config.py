# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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

# from Matthew Garret's 'firmware_config' project.

# This contains functions to manage the firmware configuration of Lenovo
# servers

import EfiDecompressor
import struct
import random
try:
    from lxml import etree
    import EfiCompressor
except ImportError:
    etree = None
    EfiCompressor = None

IMM_NETFN = 0x2e
IMM_COMMAND = 0x90
LENOVO_ENTERPRISE = [0x4d, 0x4f, 0x00]

OPEN_RO_COMMAND = [0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]
OPEN_WO_COMMAND = [0x01, 0x03, 0x01]
READ_COMMAND = [0x02]
WRITE_COMMAND = [0x03]
CLOSE_COMMAND = [0x05]
SIZE_COMMAND = [0x06]


class LenovoFirmwareConfig(object):
    def __init__(self, ipmicmd):
        if not etree:
            raise Exception("python-lxml and python-eficompressor required "
                            "for this function")
        self.connection = ipmicmd

    def imm_size(self, filename):
        data = []
        data += LENOVO_ENTERPRISE
        data += SIZE_COMMAND
        for i in range(len(filename)):
            data += [ord(filename[i])]

        response = self.connection.raw_command(netfn=IMM_NETFN,
                                               command=IMM_COMMAND, data=data)

        size = ''.join(chr(c) for c in response['data'][3:7])

        size = struct.unpack("i", size)
        return size[0]

    def imm_open(self, filename, write=False, size=None):
        response = None
        retries = 12
        data = []
        data += LENOVO_ENTERPRISE
        if write is False:
            data += OPEN_RO_COMMAND
        else:
            assert size is not None
            data += OPEN_WO_COMMAND
            hex_size = struct.pack("<I", size)
            for byte in hex_size[:4]:
                data += [ord(byte)]
            data += [0x01, 0x10]
        for i in range(len(filename)):
            data += [ord(filename[i])]
        while len(data) < 38:
            data += [0x00]

        while retries:
            retries = retries-1
            response = self.connection.raw_command(netfn=IMM_NETFN,
                                                   command=IMM_COMMAND,
                                                   data=data)
            try:
                if response['code'] == 0 or retries == 0:
                    break
            except KeyError:
                pass

            self.connection.ipmi_session.pause(5)
        filehandle = ''.join(chr(byte) for byte in response['data'][3:7])
        filehandle = struct.unpack("<I", filehandle)[0]
        return filehandle

    def imm_close(self, filehandle):
        data = []
        data += LENOVO_ENTERPRISE
        data += CLOSE_COMMAND

        hex_filehandle = struct.pack("<I", filehandle)

        for byte in hex_filehandle[:4]:
            data += [ord(byte)]

        self.connection.raw_command(netfn=IMM_NETFN,
                                    command=IMM_COMMAND, data=data)

    def imm_write(self, filehandle, size, inputdata):
        blocksize = 0xc8
        offset = 0
        remaining = size

        hex_filehandle = struct.pack("<I", filehandle)

        while remaining > 0:
            data = []
            data += LENOVO_ENTERPRISE
            data += WRITE_COMMAND
            for byte in hex_filehandle[:4]:
                data += [ord(byte)]
            hex_offset = struct.pack("<I", offset)
            for byte in hex_offset[:4]:
                data += [ord(byte)]
            if remaining < blocksize:
                amount = remaining
            else:
                amount = blocksize
            for byte in inputdata[offset:offset+amount]:
                data += [ord(byte)]
            remaining -= blocksize
            offset += blocksize
            self.connection.raw_command(netfn=IMM_NETFN, command=IMM_COMMAND,
                                        data=data)

    def imm_read(self, filehandle, size):
        blocksize = 0xc8
        offset = 0
        output = []
        remaining = size

        hex_filehandle = struct.pack("<I", filehandle)
        hex_blocksize = struct.pack("<H", blocksize)

        while remaining > 0:
            data = []
            data += LENOVO_ENTERPRISE
            data += READ_COMMAND
            for byte in hex_filehandle[:4]:
                data += [ord(byte)]
            hex_offset = struct.pack("<I", offset)
            for byte in hex_offset[:4]:
                data += [ord(byte)]
            if remaining < blocksize:
                hex_blocksize = struct.pack("<H", remaining)
            for byte in hex_blocksize[:2]:
                data += [ord(byte)]
            remaining -= blocksize
            offset += blocksize

            response = self.connection.raw_command(netfn=IMM_NETFN,
                                                   command=IMM_COMMAND,
                                                   data=data)

            output += response['data'][5:]

        return ''.join(chr(c) for c in output)

    def factory_reset(self):
        options = self.get_fw_options()
        for option in options:
            if options[option]['is_list']:
                options[option]['new_value'] = [options[option]['default']]
            else:
                options[option]['new_value'] = options[option]['default']
        self.set_fw_options(options)

    def get_fw_options(self):
        options = {}
        data = None
        for i in range(0, 15):
            filehandle = self.imm_open("config.efi")
            size = self.imm_size("config.efi")
            data = self.imm_read(filehandle, size)
            self.imm_close(filehandle)
            data = EfiDecompressor.decompress(data)
            if len(data) != 0:
                break
            self.connection.ipmi_session.pause(2)

        xml = etree.fromstring(data)

        for config in xml.iter("config"):
            lenovo_id = config.get("ID")
            for group in config.iter("group"):
                lenovo_group = group.get("ID")
                for setting in group.iter("setting"):
                    is_list = False
                    lenovo_setting = setting.get("ID")
                    protect = True if setting.get("protected") == 'true' \
                        else False
                    possible = []
                    current = None
                    default = None
                    reset = False
                    name = setting.find("mriName").text
                    help = setting.find("desc").text

                    if setting.find("list_data") is not None:
                        is_list = True
                        current = []

                    for choice in setting.iter("choice"):
                        label = choice.find("label").text
                        possible.append(label)
                        instance = choice.find("instance")
                        if instance is not None:
                            if is_list:
                                current.append(label)
                            else:
                                current = label
                        if choice.get("default") == "true":
                            default = label
                        if choice.get("reset-required") == "true":
                            reset = True
                    optionname = "%s.%s" % (lenovo_id, name)
                    options[optionname] = dict(current=current,
                                               default=default,
                                               possible=possible,
                                               pending=None,
                                               new_value=None,
                                               help=help,
                                               is_list=is_list,
                                               lenovo_id=lenovo_id,
                                               lenovo_group=lenovo_group,
                                               lenovo_setting=lenovo_setting,
                                               lenovo_reboot=reset,
                                               lenovo_protect=protect,
                                               lenovo_instance="")

        return options

    def set_fw_options(self, options):
        changes = False
        random.seed()
        ident = 'ASU-%x-%x-%x-0' % (random.getrandbits(48),
                                    random.getrandbits(32),
                                    random.getrandbits(64))

        configurations = etree.Element('configurations', ID=ident,
                                       type='update', update='ASU Client')

        for option in options.keys():
            if options[option]['new_value'] is None:
                continue
            if options[option]['current'] == options[option]['new_value']:
                continue
            if options[option]['pending'] == options[option]['new_value']:
                continue
            if (isinstance(options[option]['new_value'], str) or
                    isinstance(options[option]['new_value'], unicode)):
                # Coerce a simple string parameter to the expected list format
                options[option]['new_value'] = [options[option]['new_value']]
            options[option]['pending'] = options[option]['new_value']

            is_list = options[option]['is_list']
            count = 0
            changes = True
            config = etree.Element('config', ID=options[option]['lenovo_id'])
            configurations.append(config)
            group = etree.Element('group', ID=options[option]['lenovo_group'])
            config.append(group)
            setting = etree.Element('setting',
                                    ID=options[option]['lenovo_setting'])
            group.append(setting)

            if is_list:
                container = etree.Element('list_data')
                setting.append(container)
            else:
                container = etree.Element('enumerate_data')
                setting.append(container)

            for value in options[option]['new_value']:
                choice = etree.Element('choice')
                container.append(choice)
                label = etree.Element('label')
                label.text = value
                choice.append(label)
                if is_list:
                    count += 1
                    instance = etree.Element(
                        'instance', ID=options[option]['lenovo_instance'],
                        order=str(count))
                else:
                    instance = etree.Element(
                        'instance', ID=options[option]['lenovo_instance'])
                choice.append(instance)

        if not changes:
            return

        xml = etree.tostring(configurations)
        data = EfiCompressor.FrameworkCompress(xml, len(xml))
        filehandle = self.imm_open("asu_update.efi", write=True,
                                   size=len(data))
        self.imm_write(filehandle, len(data), data)
        self.imm_close(filehandle)
