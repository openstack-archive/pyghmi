# Copyright 2019 Lenovo Corporation
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

import pyghmi.redfish.oem.generic as generic
import pyghmi.redfish.oem.lenovo.main as lenovo

OEMMAP = {
    'Lenovo': lenovo,
}

def get_oem_handler(sysinfo, sysurl, webclient, cache):
    for oem in sysinfo.get('Oem', {}):
        if oem in OEMMAP:
            return OEMMAP[oem].get_handler(sysinfo, sysurl, webclient, cache)
    return generic.OEMHandler(sysinfo, sysurl, webclient, cache)
