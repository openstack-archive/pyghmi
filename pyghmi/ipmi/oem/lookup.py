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

import pyghmi.ipmi.oem.generic as generic
import pyghmi.ipmi.oem.lenovo.handler as lenovo
import pyghmi.ipmi.oem.ibm.handler as ibm

# The mapping comes from
# http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
# Only mapping the ones with known backends
oemmap = {
    2: ibm,
    20301: ibm,  # IBM x86 (and System X at Lenovo)
    19046: lenovo,  # Lenovo x86 (e.g. Thinkserver)
    7154: lenovo,
}


def get_oem_handler(oemid, ipmicmd):
    try:
        # Treat the Reno (x3750M4) as IBM server
        if oemid['product_id'] == 309:
            oemid['manufacturer_id'] = 20301

        return oemmap[oemid['manufacturer_id']].OEMHandler(oemid, ipmicmd)
    except KeyError:
        return generic.OEMHandler(oemid, ipmicmd)
