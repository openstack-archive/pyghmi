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

#__author__ = 'jjohnson2@lenovo.com'

import pyghmi.exceptions as pygexc
import struct


def _decode_standard_event(eventdata):
    # Ignore the generator id..
    event = {}
    if eventdata[2] != 4:
        raise pygexc.PyghmiException(
            'Unrecognized Event message version {0}'.format(eventdata[2]))
    event['sensor_type'] = eventdata[3]
    event['sensor'] = eventdata[4]
    event['deassertion'] = (eventdata[5] & 0b10000000 == 0b10000000)
    event['event_data'] = eventdata[6:]
    print repr(event)



def _sel_decode(selentry):
    selentry = bytearray(selentry)
    if selentry[2] == 2 or (selentry[2] >= 0xc0 and selentry[2] <= 0xdf):
        # Either standard, or at least the timestamp is standard
        tstamp = struct.unpack_from('<I', selentry[3:7])[0]
        print repr(tstamp)
    if selentry[2] == 2:  # ipmi defined standard format
        _decode_standard_event(selentry[7:])
    elif selentry[2] >= 0xc0 and selentry[2] <= 0xdf:
        evtoemid = selentry[7:10]
    elif selentry[2] >= 0xe0:
        # In this class of OEM message, all bytes are OEM and interpretation
        # is wholly left up to the OEM layer, using the OEM ID of the BMC
        selentry[3:]

    return 1

def _fetch_entries(ipmicmd, startat, targetlist, rsvid=0):
    curr = startat
    while curr != 0xffff:
        endat = curr
        reqdata = bytearray(struct.pack('<HHH', rsvid, curr, 0xff00))
        rsp = ipmicmd.xraw_command(netfn=0xa, command=0x43, data=reqdata)
        curr = struct.unpack_from('<H', rsp['data'][:2])[0]
        targetlist.append(_sel_decode(rsp['data'][2:]))
    return endat


def fetch_sel(ipmicmd, clear=False):
    """Fetch SEL entries

    Return an iterable of SEL entries.  If clearing is requested,
    the fetch and clear will be done as an atomic operation, assuring
    no entries are dropped.

    :param ipmicmd: The Command object to use to interrogate
    :param clear: Whether to clear the entries upon retrieval.
    """
    records = []
    # First we do a fetch all without reservation.  This way we reduce the risk
    # of having a long lived reservation that gets canceled in the middle
    endat = _fetch_entries(ipmicmd, 0, records, 0)
    if clear:
        # To do clear, we make a reservation first...
        rsp = ipmicmd.xraw_command(netfn=0xa, command=0x42)
        rsvid = struct.unpack_from('<H', rsp['data'])
        # Then we refetch the tail with reservation (in case something changed)
        del records[-1]  # remove the record that's about to be duplicated
        _fetch_entries(ipmicmd, endat, records, rsvid)
        # finally clear the SEL
        # 0XAA means start initiate, 0x523c43 is 'RCL' or 'CLR' backwards
        clrdata = struct.pack('<HI', rsvid, 0xAA523C43)
        ipmicmd.xraw_command(netfn=0xa, command=0x47, data=clrdata)
    # Now to fixup the record timestamps... first we need to get the BMC
    # opinion of current time
    rsp = ipmicmd.xraw_command(netfn=0xa, command=0x48)
    # The specification declares an epoch and all that, but we really don't
    # care.  We instead just focus on differences from the 'present'
    nowtime = struct.unpack_from('<I', rsp['data'])


# Get SEL Info:
# self.ipmicmd.raw_command(netfn=0xa, command=0x40)
# Reserve SEL:
# netfn=0xa, command=0x42
# clear SEL:
# netfn=0xa, command=0x47
# get SEL time:
# netfn=0xa, command=0x48
# add sel entry: netfn=0xa, command=0x44
# get SEL entry: netfn=0xa, command=0x43
# Hypothetcially, might be abble to do a manual rotation through
# strategic use of clear and add if people care to do an ageout scheme
#
