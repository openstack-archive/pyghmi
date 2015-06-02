# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015 Lenovo Corporation
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


class OEMHandler(object):
    """Handler class for OEM capabilities.

    Any vendor wishing to implement OEM extensions should look at this
    base class for an appropriate interface.  If one does not exist, this
    base class should be extended.  At initialization an OEM is given
    a dictionary with product_id, device_id, manufacturer_id, and
    device_revision as keys in a dictionary, along with an ipmi Command object
    """
    def __init__(self, oemid, ipmicmd):
        pass

    def process_event(self, event, ipmicmd, seldata):
        """Modify an event according with OEM understanding.

        Given an event, allow an OEM module to augment it.  For example,
        event data fields can have OEM bytes.  Other times an OEM may wish
        to apply some transform to some field to suit their conventions.
        """
        event['oem_handler'] = None
        evdata = event['event_data_bytes']
        if evdata[0] & 0b11000000 == 0b10000000:
            event['oem_byte2'] = evdata[1]
        if evdata[0] & 0b110000 == 0b100000:
            event['oem_byte3'] = evdata[2]

    def get_oem_inventory_descriptions(self):
        """Get descriptions of available additional inventory items

        OEM implementation may provide additional records not indicated
        by FRU locator SDR records.  An implementation is expected to
        implement this function to list component names that would map to
        OEM behavior beyond the specification.  It should return an iterable
        of names"""
        return ()

    def process_fru(self, fru):
        """Modify a fru entry with OEM understanding.

        Given a fru, clarify 'extra' fields according to OEM rules and
        return the transformed data structure.  If OEM processes, it is
        expected that it sets 'oem_parser' to the name of the module.  For
        clients passing through data, it is suggested to pass through
        board/product/chassis_extra_data arrays if 'oem_parser' is None,
        and mask those fields if not None.  It is expected that OEMs leave
        the fields intact so that if client code hard codes around the
        ordered lists that their expectations are not broken by an update.
        """
        # In the generic case, just pass through
        if fru is None:
            return fru
        fru['oem_parser'] = None
        return fru
