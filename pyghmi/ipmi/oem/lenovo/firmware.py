# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from pyghmi.ipmi.oem.lenovo.inventory import EntryField, \
    parse_inventory_category_entry

firmware_fields = (
    EntryField("Revision", "B"),
    EntryField("Bios", "16s"),
    EntryField("Operational ME", "10s"),
    EntryField("Recovery ME", "10s"),
    EntryField("RAID 1", "16s"),
    EntryField("RAID 2", "16s"),
    EntryField("Mezz 1", "16s"),
    EntryField("Mezz 2", "16s"),
    EntryField("BMC", "16s"),
    EntryField("LEPT", "16s"),
    EntryField("PSU 1", "16s"),
    EntryField("PSU 2", "16s"),
    EntryField("CPLD", "16s"),
    EntryField("LIND", "16s"),
    EntryField("WIND", "16s"),
    EntryField("DIAG", "16s"))


def parse_firmware_info(raw):
    bytes_read, data = parse_inventory_category_entry(raw, firmware_fields)
    del data['Revision']
    for key in data:
        yield(key, {'version': data[key]})


def get_categories():
    return {
        "firmware": {
            "idstr": "FW Version",
            "parser": parse_firmware_info,
            "command": {
                "netfn": 0x06,
                "command": 0x59,
                "data": (0x00, 0xc7, 0x00, 0x00)
            }
        }
    }
