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

ntp_config_fields = (
    EntryField("Enabled", "B"),
    EntryField("Primary Server", "127s"),
    EntryField("Secondary Server", "127s"))

def parse_ntp_config_info(raw):
    bytes_read, data = parse_inventory_category_entry(raw, ntp_config_fields)
    return data


def get_categories():
    return {
        "ntp_config": {
            "idstr": "NTP configuration",
            "parser": parse_ntp_config_info,
            "command": {
                "netfn": 0x32,
                "command": 0xa7,
                "data": ()
            }
        }
    }
