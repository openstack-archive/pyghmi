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

import socket
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
    return '{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:04X}{5:08X}'.format(
        lebytes[0], lebytes[1], lebytes[2], bebytes[0], bebytes[1], bebytes[2])


def urlsplit(url):
    """Split an arbitrary url into protocol, host, rest

    The standard urlsplit does not want to provide 'netloc' for arbitrary
    protocols, this works around that.

    :param url: The url to split into component parts
    """
    proto, rest = url.split(':', 1)
    host = ''
    if rest[:2] == '//':
        host, rest = rest[2:].split('/', 1)
        rest = '/' + rest
    return proto, host, rest


def get_ipv4(hostname):
    """Get list of ipv4 addresses for hostname

    """
    addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET,
                                  socket.SOCK_STREAM)
    return [addrinfo[x][4][0] for x in xrange(len(addrinfo))]
