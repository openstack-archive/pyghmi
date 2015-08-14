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

cpu_fields = (
    EntryField("index", "B"),
    EntryField("Cores", "B"),
    EntryField("Threads", "B"),
    EntryField("Manufacturer", "13s"),
    EntryField("Family", "30s"),
    EntryField("Model", "30s"),
    EntryField("Stepping", "3s"),
    EntryField("Maximum Frequency", "<I",
               valuefunc=lambda v: str(v) + " MHz"),
    EntryField("Reserved", "h", include=False))


def parse_cpu_info(raw):
    return parse_inventory_category_entry(raw, cpu_fields)


def get_categories():
    return {
        "cpu": {
            "idstr": "CPU {0}",
            "parser": parse_cpu_info,
            "command": {
                "netfn": 0x06,
                "command": 0x59,
                "data": (0x00, 0xc1, 0x01, 0x00)
            }
        }
    }
