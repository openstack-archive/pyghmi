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

psu_type = {
    0b0001: "Other",
    0b0010: "Unknown",
    0b0011: "Linear",
    0b0100: "Switching",
    0b0101: "Battery",
    0b0110: "UPS",
    0b0111: "Converter",
    0b1000: "Regulator",
}
psu_status = {
    0b001: "Other",
    0b010: "Unknown",
    0b011: "OK",
    0b100: "Non-critical",
    0b101: "Critical; power supply has failed and has been taken off-line"
}
psu_voltage_range_switch = {
    0b0001: "Other",
    0b0010: "Unknown",
    0b0011: "Manual",
    0b0100: "Auto-switch",
    0b0101: "Wide range",
    0b0110: "Not applicable"
}


def psu_status_word_slice(w, s, e):
    return int(w[-e-1:-s], 2)


def psu_status_word_bit(w, b):
    return int(w[-b-1])


def psu_status_word_parser(word):
    fields = {}
    word = "{0:016b}".format(word)

    fields["DMTF Power Supply Type"] = \
        psu_type.get(psu_status_word_slice(word, 10, 13), "Invalid")

    # fields["Status"] = \
    #    psu_status.get(psu_status_word_slice(word, 7, 9), "Invalid")

    fields["DMTF Input Voltage Range"] = \
        psu_voltage_range_switch.get(
            psu_status_word_slice(word, 3, 6),
            "Invalid"
        )

    # Power supply is unplugged from the wall
    fields["Unplugged"] = \
        bool(psu_status_word_bit(word, 2))

    # fields["Power supply is present"] = \
    #    bool(psu_status_word_bit(word, 1))

    # Power supply is hot-replaceable
    fields["Hot Replaceable"] = \
        bool(psu_status_word_bit(word, 0))

    return fields

psu_fields = (
    EntryField("index", "B"),
    EntryField("Presence State", "B", presence=True),
    EntryField("Capacity W", "<H"),
    EntryField("Board manufacturer", "18s"),
    EntryField("Board model", "18s"),
    EntryField("Board manufacture date", "10s"),
    EntryField("Board serial number", "34s"),
    EntryField("Board manufacturer revision", "5s"),
    EntryField("Board product name", "10s"),
    EntryField("PSU Asset Tag", "10s"),
    EntryField(
        "PSU Redundancy Status",
        "B",
        valuefunc=lambda v: "Not redundant" if v == 0x00 else "Redundant"
    ),
    EntryField(
        "PSU Status Word",
        "<H",
        valuefunc=psu_status_word_parser, multivaluefunc=True
    )
)


def parse_psu_info(raw):
    return parse_inventory_category_entry(raw, psu_fields)


def get_categories():
    return {
        "psu": {
            "idstr": "Power Supply {0}",
            "parser": parse_psu_info,
            "command": {
                "netfn": 0x06,
                "command": 0x59,
                "data": (0x00, 0xc6, 0x00, 0x00)
            }
        }
    }
