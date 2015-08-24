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

raid_drive_fields = (
    EntryField("index", "B"),
    EntryField("VendorID", "64s"),
    EntryField("Size", "I",
               valuefunc=lambda v: str(v) + " MB"),
    EntryField("MediaType", "B", mapper={
        0x00: "HDD",
        0x01: "SSD",
        0x02: "SSM_FLASH"
    }),
    EntryField("InterfaceType", "B", mapper={
        0x00: "Unknown",
        0x01: "ParallelSCSI",
        0x02: "SAS",
        0x03: "SATA",
        0x04: "FC"
    }),
    EntryField("FormFactor", "B", mapper={
        0x00: "Unknown",
        0x01: "2.5in",
        0x02: "3.5in"
    }),
    EntryField("LinkSpeed", "B", mapper={
        0x00: "Unknown",
        0x01: "1.5 Gb/s",
        0x02: "3.0 Gb/s",
        0x03: "6.0 Gb/s",
        0x04: "12.0 Gb/s"
    }),
    EntryField("SlotNumber", "B"),
    EntryField("DeviceState", "B", mapper={
        0x00: "active",
        0x01: "stopped",
        0xff: "transitioning"
    }),
    # There seems to be an undocumented byte at the end
    EntryField("Reserved", "B", include=False))


def parse_raid_drive_info(raw):
    return parse_inventory_category_entry(raw, raid_drive_fields)


def get_categories():
    return {
        "raid_raid_drive": {
            "idstr": "RAID Drive {0}",
            "parser": parse_raid_drive_info,
            "command": {
                "netfn": 0x06,
                "command": 0x59,
                "data": (0x00, 0xc5, 0x00, 0x00)
            }
        }
    }
