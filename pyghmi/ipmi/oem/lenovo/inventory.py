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

import struct

categories = {}


def register_inventory_category(module):
    c = module.get_categories()
    for id in c:
        categories[id] = c[id]


class EntryField(object):
    """Store inventory field parsing options.

    Represents an inventory field and its options for the custom requests to a
    ThinkServer's BMC.

    :param name: the name of the field
    :param fmt: the format of the field (see struct module for details)
    :param include: whether to include the field in the parse output
    :param mapper: a dictionary mapping values to new values for the parse
                   output
    :param valuefunc: a function to be called to change the value in the last
                      step of the build process.
    :param presence: whether the field indicates presence. In this case, the
                     field will not be included. If the value is false, the
                     item will be discarded.
    """
    def __init__(self, name, fmt, include=True, mapper=None, valuefunc=None,
                 multivaluefunc=False, presence=False):
        self.name = name
        self.fmt = fmt
        self.include = include
        self.mapper = mapper
        self.valuefunc = valuefunc
        self.multivaluefunc = multivaluefunc
        self.presence = presence


# General parameter parsing functions
def parse_inventory_category(name, info, countable=True):
    """Parses every entry in an inventory category (CPU, memory, PCI, drives,
    etc).

    Expects the first byte to be a count of the number of entries, followed
    by a list of elements to be parsed by a dedicated parser (below).

    :param name: the name of the parameter (e.g.: "cpu")
    :param info: a list of integers with raw data read from an IPMI requests
    :param countable: whether the data have an entries count field

    :returns: dict -- a list of entries in the category.
    """
    raw = info["data"][1:]

    cur = 0
    if countable:
        count = struct.unpack("B", raw[cur])[0]
        cur += 1
    else:
        count = 0
    discarded = 0

    entries = []
    while cur < len(raw):
        read, cpu = categories[name]["parser"](raw[cur:])
        cur = cur + read
        # Account for discarded entries (because they are not present)
        if cpu is None:
            discarded += 1
            continue
        if not countable:
            # count by myself
            count += 1
            cpu["index"] = count
        entries.append(cpu)

    # TODO(avidal): raise specific exception to point that there's data left in
    # the buffer
    if cur != len(raw):
        raise Exception
    # TODO(avidal): raise specific exception to point that the number of
    # entries is different than the expected
    if count - discarded != len(entries):
        raise Exception
    return entries


def parse_inventory_category_entry(raw, fields):
    """Parses one entry in an inventory category.

    :param raw: the raw data to the entry. May contain more than one entry,
                only one entry will be read in that case.
    :param fields: an iterable of EntryField objects to be used for parsing the
                   entry.

    :returns: dict -- a tuple with the number of bytes read and a dictionary
                      representing the entry.
    """
    r = raw

    obj = {}
    bytes_read = 0
    discard = False
    for field in fields:
        value = struct.unpack_from(field.fmt, r)[0]
        read = struct.calcsize(field.fmt)
        bytes_read += read
        r = r[read:]
        # If this entry is not actually present, just parse and then discard it
        if field.presence and not bool(value):
            discard = True
        if not field.include:
            continue

        if (field.fmt[-1] == "s"):
            value = value.rstrip("\x00")
        if (field.mapper and value in field.mapper):
            value = field.mapper[value]
        if (field.valuefunc):
            value = field.valuefunc(value)

        if not field.multivaluefunc:
            obj[field.name] = value
        else:
            for key in value:
                obj[key] = value[key]

    if discard:
        obj = None
    return bytes_read, obj
