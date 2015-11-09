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

dimm_fields = (
    EntryField("index", "B"),
    EntryField("manufacture_location", "B"),
    EntryField("channel_number", "B"),
    EntryField("module_type", "10s"),
    EntryField("ddr_voltage", "10s"),
    EntryField("speed", "<h",
               valuefunc=lambda v: str(v) + " MHz"),
    EntryField("capacity_mb", "<h",
               valuefunc=lambda v: v*1024),
    EntryField("manufacturer", "30s"),
    EntryField("serial", ">I",
               valuefunc=lambda v: hex(v)[2:]),
    EntryField("model", "21s"),
    EntryField("reserved", "h", include=False)
)


def parse_dimm_info(raw):
    return parse_inventory_category_entry(raw, dimm_fields)


def get_categories():
    return {
        "dimm": {
            "idstr": "DIMM {0}",
            "parser": parse_dimm_info,
            "command": {
                "netfn": 0x06,
                "command": 0x59,
                "data": (0x00, 0xc1, 0x02, 0x00)
            },
            "workaround_bmc_bug": True
        }
    }
