# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015 IBM Corporation
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

import pyghmi.ipmi.oem.lenovo as lenovo

# The mapping comes from
# http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
# Only mapping the ones with known backends
oemmap = {
    20301: lenovo,  # IBM x86 (and System X at Lenovo)
    19046: lenovo,  # Lenovo x86 (e.g. Thinkserver)
}

def get_oem_handler(oemid, ipmicmd):
    try:
        return oemid['manufacturer_id'].OEMHandler(oemid, ipmicmd)
    except KeyError:
        return OEMHandler(oemid, ipmicmd)

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




