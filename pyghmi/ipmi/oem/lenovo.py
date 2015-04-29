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

import pyghmi.ipmi.oem.generic as generic
import pyghmi.ipmi.private.util as util


class OEMHandler(generic.OEMHandler):
    # noinspection PyUnusedLocal
    def __init__(self, oemid, ipmicmd):
        # will need to retain data to differentiate
        # variations.  For example System X versus Thinkserver
        self.oemid = oemid

    def process_fru(self, fru):
        if fru is None:
            return fru
        if (self.oemid['manufacturer_id'] == 19046 and
                self.oemid['device_id'] == 32):
            fru['oem_parser'] = 'lenovo'
            # Thinkserver lays out specific interpretation of the
            # board extra fields
            _, _, wwn1, wwn2, mac1, mac2 = fru['board_extra']
            if wwn1 not in ('0000000000000000', ''):
                fru['WWN 1'] = wwn1
            if wwn2 not in ('0000000000000000', ''):
                fru['WWN 2'] = wwn2
            if mac1 not in ('00:00:00:00:00:00', ''):
                fru['MAC Address 1'] = mac1
            if mac2 not in ('00:00:00:00:00:00', ''):
                fru['MAC Address 2'] = mac2
            # The product_extra field is UUID as the system would present
            # in DMI.  This is different than the two UUIDs that
            # it returns for get device and get system uuid...
            byteguid = fru['product_extra'][0]
            # It can present itself as claiming to be ASCII when it
            # is actually raw hex.  As a result it triggers the mechanism
            # to strip \x00 from the end of text strings.  Work around this
            # by padding with \x00 to the right if the string is not 16 long
            byteguid.extend('\x00' * (16 - len(byteguid)))
            fru['UUID'] = util.decode_wireformat_uuid(byteguid)
            return fru
        else:
            fru['oem_parser'] = None
            return fru
