# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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

from ctypes import addressof, c_int, c_long, c_short, c_ubyte, c_uint
from ctypes import cast, create_string_buffer, POINTER, pointer, sizeof
from ctypes import Structure
import fcntl
import pyghmi.ipmi.private.util as iutil
from select import select


class IpmiMsg(Structure):
    _fields_ = [('netfn', c_ubyte),
                ('cmd', c_ubyte),
                ('data_len', c_short),
                ('data', POINTER(c_ubyte))]


class IpmiSystemInterfaceAddr(Structure):
    _fields_ = [('addr_type', c_int),
                ('channel', c_short),
                ('lun', c_ubyte)]


class IpmiRecv(Structure):
    _fields_ = [('recv_type', c_int),
                ('addr', POINTER(IpmiSystemInterfaceAddr)),
                ('addr_len', c_uint),
                ('msgid', c_long),
                ('msg', IpmiMsg)]


class IpmiReq(Structure):
    _fields_ = [('addr', POINTER(IpmiSystemInterfaceAddr)),
                ('addr_len', c_uint),
                ('msgid', c_long),
                ('msg', IpmiMsg)]


_IONONE = 0
_IOWRITE = 1
_IOREAD = 2
IPMICTL_SET_MY_ADDRESS_CMD = _IOREAD << 30 | sizeof(c_uint) << 16 | \
    ord('i') << 8 | 17  # from ipmi.h
IPMICTL_SEND_COMMAND = _IOREAD << 30 | sizeof(IpmiReq) << 16 | \
    ord('i') << 8 | 13  # from ipmi.h
# next is really IPMICTL_RECEIVE_MSG_TRUNC, but will only use that
IPMICTL_RECV = (_IOWRITE | _IOREAD) << 30 | sizeof(IpmiRecv) << 16 | \
    ord('i') << 8 | 11  # from ipmi.h
BMC_SLAVE_ADDR = c_uint(0x20)
CURRCHAN = 0xf
ADDRTYPE = 0xc


class Session(object):
    def __init__(self, devnode='/dev/ipmi0'):
        """Create a local session inband

        :param: devnode: The path to the ipmi device
        """
        self.ipmidev = open(devnode, 'rw')
        fcntl.ioctl(self.ipmidev, IPMICTL_SET_MY_ADDRESS_CMD, BMC_SLAVE_ADDR)
        # the interface is initted, create some reusable memory for our session
        self.databuffer = create_string_buffer(4096)
        self.req = IpmiReq()
        self.rsp = IpmiRecv()
        self.addr = IpmiSystemInterfaceAddr()
        self.req.msg.data = cast(addressof(self.databuffer), POINTER(c_ubyte))
        self.rsp.msg.data = self.req.msg.data
        self.userid = None
        self.password = None

    def await_reply(self):
        rd, _, _ = select((self.ipmidev,), (), (), 1)
        while not rd:
            rd, _, _ = select((self.ipmidev,), (), (), 1)

    @property
    def parsed_rsp(self):
        response = {'netfn': self.rsp.msg.netfn, 'command': self.rsp.msg.cmd,
                    'code': ord(self.databuffer.raw[0]),
                    'data': list(bytearray(
                        self.databuffer.raw[1:self.rsp.msg.data_len]))}
        errorstr = iutil.get_ipmi_error(response)
        if errorstr:
            response['error'] = errorstr
        return response

    def raw_command(self,
                    netfn,
                    command,
                    data=(),
                    bridge_request=None,
                    retry=True,
                    delay_xmit=None,
                    timeout=None,
                    waitall=False):
        self.addr.channel = CURRCHAN
        self.addr.addr_type = ADDRTYPE
        self.req.addr_len = sizeof(IpmiSystemInterfaceAddr)
        self.req.addr = pointer(self.addr)
        self.req.msg.netfn = netfn
        self.req.msg.cmd = command
        data = buffer(bytearray(data))
        self.databuffer[:len(data)] = data[:len(data)]
        self.req.msg.data_len = len(data)
        fcntl.ioctl(self.ipmidev, IPMICTL_SEND_COMMAND, self.req)
        self.await_reply()
        self.rsp.msg.data_len = 4096
        self.rsp.addr = pointer(self.addr)
        self.rsp.addr_len = sizeof(IpmiSystemInterfaceAddr)
        fcntl.ioctl(self.ipmidev, IPMICTL_RECV, self.rsp)
        return self.parsed_rsp


def main():
    a = Session('/dev/ipmi0')
    print(repr(a.raw_command(0, 1)))


if __name__ == '__main__':
    main()
