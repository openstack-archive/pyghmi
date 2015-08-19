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

fwversion_fields = (
    EntryField("Revision", "B"),
    EntryField("Bios_Version", "16s"),
    EntryField("Operational_ME_Version", "10s"),
    EntryField("Recovery_ME_Version", "10s"),
    EntryField("RAID1_Version", "16s"),
    EntryField("RAID2_Version", "16s"),
    EntryField("Mezz1_Version", "16s"),
    EntryField("Mezz2_Version", "16s"),
    EntryField("BMC_Version", "16s"),
    EntryField("LEPT_Version", "16s"),
    EntryField("PSU1_Version", "16s"),
    EntryField("PSU2_Version", "16s"),
    EntryField("CPLD_Version", "16s"),
    EntryField("LIND_Version", "16s"),
    EntryField("WIND_Version", "16s"),
    EntryField("DIAG_Version", "16s"))


def parse_fwversion_info(raw):
    return parse_inventory_category_entry(raw, fwversion_fields)


def get_categories():
    return {
        "fwversion": {
            "idstr": "FW Version",
            "parser": parse_fwversion_info,
            "command": {
                "netfn": 0x06,
                "command": 0x59,
                "data": (0x00, 0xc7, 0x00, 0x00)
            }
        }
    }
