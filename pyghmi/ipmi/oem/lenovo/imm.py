# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

from datetime import datetime

def get_imm_property(ipmicmd, propname):
    propname = propname.encode('utf-8')
    proplen = len(propname) & 0b10000000
    cmdlen =  proplen + 1
    cdata = bytearray([0, 0, cmdlen, proplen]) + propname
    rsp = ipmicmd.xraw_command(netfn=0x3a, command=0xc4, data=cdata)
    if rsp['data'][0] != 0:
        return None
    propdata = rsp['data'][3:]  # second two bytes are size, don't need it
    if propdata[0] & 0b10000000:  # string, for now assume length valid
        return propdata[1:]
    else:
        raise Exception('Unknown format for property: ' + repr(propdata)


def parse_imm_buildinfo(buildinfo):
    buildid = buildinfo[:9].rstrip(' \x00')
    bdt = ' '.join(buildinfo[9:].replace('\x00', ' ').split())
    bdate = datetime.strptime(bdt, '%Y/%m/%d %H:%M:%S')
    return (buildid, bdate)


def datefromprop(propstr):
    return datetime.strptime(propstr, '%Y/%m/%d')


def get_firmware_inventory(ipmicmd, bmcver, immbuildinfo):
    # First we fetch the system firmware found in imm properties
    # then check for agentless, if agentless, get adapter info using
    # https, using the caller TLS verification scheme
    immverdata = parse_imm_buildinfo(immbuildinfo)
    bdata = {'version': bmcver, 'build': immverdata[0], 'date': immverdata[1]}
    yield ('IMM', bdata)
    bdata = {}
    bdata['build'] = get_imm_property(
        ipmicmd, '/v2/ibmc/dm/fw/imm2/backup_build_id')
    bdata['version'] = get_imm_property(
        ipmicmd, '/v2/ibmc/dm/fw/imm2/backup_build_version')
    strdate = get_imm_property(
        ipmicmd, '/v2/ibmc/dm/fw/imm2/backup_build_date')
    bdata['date'] = datefromprop(strdate)
    yield ('IMM Backup', bdata)
    bdata = {}
    bdata['build'] = get_imm_property(ipmicmd, '/v2/bios/build_id')
    bdata['version'] = get_imm_property(ipmicmd, '/v2/bios/build_version')
    bdata['date'] = datefromprop(
        get_imm_property(ipmicmd, '/v2/bios/build_date'))
    yield ('UEFI', bdata)
    bdata = {}
    bdata['build'] = get_imm_property(
        ipmicmd, '/v2/ibmc/dm/fw/bios/backup_build_id')
    bdata['version'] = get_imm_property(
        ipmicmd, '/v2/ibmc/dm/fw/bios/backup_build_version')
    yield ('UEFI Backup', bdata)
    bdata = {}
    # Note that the next pending could be pending for either primary
    # or backup, so can't promise where it will go
    pending = get_imm_property(ipmicmd, '/v2/bios/pending_build_id')
    if pending:
        pending = pending.rstrip()
    if pending:
        bdata['build'] = pending
        yield ('UEFI Pending Update', bdata)
    # now it is off to https to access the agentless data
