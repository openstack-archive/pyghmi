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


def decode_wireformat_uuid(rawguid):
    """Decode a wire format UUID

    It handles the rather particular scheme where half is little endian
    and half is big endian.  It returns a string like dmidecode would output.
    """
    if isinstance(rawguid, list):
        rawguid = bytearray(rawguid)
    lebytes = struct.unpack_from('<IHH', buffer(rawguid[:8]))
    bebytes = struct.unpack_from('>HHI', buffer(rawguid[8:]))
    return '{0:04X}-{1:02X}-{2:02X}-{3:02X}-{4:02X}{5:04X}'.format(
        lebytes[0], lebytes[1], lebytes[2], bebytes[0], bebytes[1], bebytes[2])
