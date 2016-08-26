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
import pyghmi.exceptions as pygexc


class FFDCFetcher(object):

    def __init__(self, ipmicmd):
        self.ipmicmd = ipmicmd

    def check_ffdc_status(self, wait=True):
        """check the ffdc collection status
        """
        try:
            status_rep = self.ipmicmd.xraw_command(
                netfn=0x3a,
                command=0x4d,
                data=[1]
            )
            while wait and ord(status_rep['data'][0]) == 0x02:
                self.ipmicmd.wait_for_rsp(5)
                status_rep = self.ipmicmd.xraw_command(
                    netfn=0x3a,
                    command=0x4d,
                    data=[1]
                )
            return ord(status_rep['data'][0])
        except pygexc.IpmiException as ie:
            print ie['error']
            return 0x00

    def fetch_datastore_name(self, name, filename, waitforready=False):
        # check the ffdc status
        status = self.check_ffdc_status(waitforready)

        # if the ffdc is ready
        if status == 0x01:
            dsname = list(struct.unpack('%dB' % len(name), name))
            rqdata = [0x4d, 0x4f, 0x0, 6] + dsname
            checkdssize = self.ipmicmd.raw_command(
                netfn=0x2e,
                command=0x90,
                data=rqdata
            )
            while waitforready and checkdssize['code'] == 0xa:
                self.ipmicmd.wait_for_rsp(5)
                checkdssize = self.ipmicmd.raw_command(
                    netfn=0x2e,
                    command=0x90,
                    data=rqdata
                )
            if 'error' in checkdssize:
                print checkdssize['error']
                return False
        else:
            return False

        totalsize = struct.unpack(
            '<I', struct.pack('4B', *checkdssize['data'][3:7]))[0]

        # get the ffdc handle
        rq1 = [0x4d, 0x4f, 0x0, 1, 1, 0]
        rq2 = checkdssize['data'][3:7] + [0, 30]
        rqdata = rq1 + rq2 + dsname
        opends = self.ipmicmd.raw_command(
            netfn=0x2e,
            command=0x90,
            data=rqdata
        )
        dshandle = opends['data'][3:7]
        dsout = open(filename, 'wb')
        curroffset = 0
        chunksize = 230

        # read the ffdc
        while chunksize > 0:
            curroff = list(struct.unpack('4B', struct.pack('<I', curroffset)))
            if totalsize < (curroffset + chunksize):
                chunksize = totalsize - curroffset
            if chunksize > 0:
                currchunk = list(
                    struct.unpack('2B', struct.pack('<H', chunksize))
                )
                rqdata = [0x4d, 0x4f, 0x0, 2] + dshandle + curroff + currchunk
                readit = self.ipmicmd.raw_command(
                    netfn=0x2e,
                    command=0x90,
                    data=rqdata
                )
                if readit['code'] != 0:
                    return False
                dsout.write(struct.pack(
                    '%dB' % len(readit['data'][5:]), *readit['data'][5:])
                )
                curroffset += chunksize
        dsout.close()

        return True

    def fetch_ffdc_file(self, filename):
        # check if there is ffdc in progress
        status = self.check_ffdc_status(False)
        if status == 0x02:
            self.check_ffdc_status()
        else:
            begindump = self.ipmicmd.raw_command(
                netfn=0x3a,
                command=0x49,
                data=[1]
            )
            if 'error' in begindump:
                print begindump['error']
                return False
            self.ipmicmd.wait_for_rsp(5)

        # fetch the ffdc
        return self.fetch_datastore_name(
            b'ffdc.tgz',
            filename,
            waitforready=True
        )
