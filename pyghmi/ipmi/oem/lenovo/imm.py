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
import json
from pyghmi.ipmi.private.session import _monotonic_time
import pyghmi.util.webclient as webclient
import urllib


def get_imm_property(ipmicmd, propname):
    propname = propname.encode('utf-8')
    proplen = len(propname) | 0b10000000
    cmdlen = len(propname) + 1
    cdata = bytearray([0, 0, cmdlen, proplen]) + propname
    rsp = ipmicmd.xraw_command(netfn=0x3a, command=0xc4, data=cdata)
    rsp['data'] = bytearray(rsp['data'])
    if rsp['data'][0] != 0:
        return None
    propdata = rsp['data'][3:]  # second two bytes are size, don't need it
    if propdata[0] & 0b10000000:  # string, for now assume length valid
        return str(propdata[1:]).rstrip(' \x00')
    else:
        raise Exception('Unknown format for property: ' + repr(propdata))


def get_imm_webclient(imm, certverify, uid, password):
    wc = webclient.SecureHTTPConnection(imm, 443,
                                        verifycallback=certverify)
    try:
        wc.connect()
    except Exception:
        return None
    adata = urllib.urlencode({'user': uid,
                              'password': password,
                              'SessionTimeout': 60
                              })
    headers = {'Connection': 'keep-alive',
               'Content-Type': 'application/x-www-form-urlencoded'}
    wc.request('POST', '/data/login', adata, headers)
    rsp = wc.getresponse()
    if rsp.status == 200:
        rspdata = json.loads(rsp.read())
        if rspdata['authResult'] == '0' and rspdata['status'] == 'ok':
            return wc


def parse_imm_buildinfo(buildinfo):
    buildid = buildinfo[:9].rstrip(' \x00')
    bdt = ' '.join(buildinfo[9:].replace('\x00', ' ').split())
    bdate = datetime.strptime(bdt, '%Y/%m/%d %H:%M:%S')
    return (buildid, bdate)


def datefromprop(propstr):
    if propstr is None:
        return None
    return datetime.strptime(propstr, '%Y/%m/%d')


def fetch_grouped_properties(ipmicmd, groupinfo):
    retdata = {}
    for keyval in groupinfo:
        retdata[keyval] = get_imm_property(ipmicmd, groupinfo[keyval])
        if keyval == 'date':
            retdata[keyval] = datefromprop(retdata[keyval])
    returnit = False
    for keyval in list(retdata):
        if retdata[keyval] in (None, ''):
            del retdata[keyval]
        else:
            returnit = True
    if returnit:
        return retdata


def fetch_adapter_firmware(ipmicmd, certverify):
    adapterdata = None
    try:
        vintage = ipmicmd.ipmi_session.lenovo_cached_adapters[1]
        if vintage > _monotonic_time() - 30:
            adapterdata = ipmicmd.ipmi_session.lenovo_cached_adapters[0]
    except AttributeError:
        pass
    if not adapterdata:
        wc = get_imm_webclient(ipmicmd.bmc, certverify,
                               ipmicmd.ipmi_session.userid,
                               ipmicmd.ipmi_session.password)
        if not wc:
            return
        wc.request('GET', '/designs/imm/dataproviders/imm_adapters.php')
        rsp = wc.getresponse()
        if rsp.status == 200:
            adapterdata = json.loads(rsp.read())
            ipmicmd.ipmi_session.lenovo_cached_adapters = (adapterdata,
                                                           _monotonic_time())
        wc.request('GET', '/data/logout')
    if adapterdata:
        for adata in adapterdata['items']:
            aname = adata['adapter.adapterName']
            donenames = set([])
            for fundata in adata['adapter.functions']:
                fdata = fundata.get('firmwares', ())
                for firm in fdata:
                    fname = firm['firmwareName']
                    if '.' in fname:
                        fname = firm['description']
                    if fname in donenames:
                        # ignore redundant entry
                        continue
                    donenames.add(fname)
                    bdata = {}
                    if 'versionStr' in firm and firm['versionStr']:
                        bdata['version'] = firm['versionStr']
                    if ('releaseDate' in firm and
                            firm['releaseDate'] and
                            firm['releaseDate'] != 'N/A'):
                        bdata['date'] = datetime.strptime(firm['releaseDate'],
                                                          '%m/%d/%Y')
                    yield ('{0} {1}'.format(aname, fname), bdata)


def get_firmware_inventory(ipmicmd, bmcver, certverify):
    # First we fetch the system firmware found in imm properties
    # then check for agentless, if agentless, get adapter info using
    # https, using the caller TLS verification scheme
    rsp = ipmicmd.xraw_command(netfn=0x3a, command=0x50)
    immverdata = parse_imm_buildinfo(rsp['data'])
    bdata = {'version': bmcver, 'build': immverdata[0], 'date': immverdata[1]}
    yield ('IMM', bdata)
    bdata = fetch_grouped_properties(ipmicmd, {
        'build': '/v2/ibmc/dm/fw/imm2/backup_build_id',
        'version': '/v2/ibmc/dm/fw/imm2/backup_build_version',
        'date': '/v2/ibmc/dm/fw/imm2/backup_build_date'})
    if bdata:
        yield ('IMM Backup', bdata)
        bdata = fetch_grouped_properties(ipmicmd, {
            'build': '/v2/ibmc/trusted_buildid',
        })
    if bdata:
        yield ('IMM Trusted Image', bdata)
    bdata = fetch_grouped_properties(ipmicmd, {
        'build': '/v2/bios/build_id',
        'version': '/v2/bios/build_version',
        'date': '/v2/bios/build_date'})
    if bdata:
        yield ('UEFI', bdata)
    bdata = fetch_grouped_properties(ipmicmd, {
        'build': '/v2/ibmc/dm/fw/bios/backup_build_id',
        'version': '/v2/ibmc/dm/fw/bios/backup_build_version'})
    if bdata:
        yield ('UEFI Backup', bdata)
    # Note that the next pending could be pending for either primary
    # or backup, so can't promise where it will go
    bdata = fetch_grouped_properties(ipmicmd, {
        'build': '/v2/bios/pending_build_id'})
    if bdata:
        yield ('UEFI Pending Update', bdata)
    for firm in fetch_adapter_firmware(ipmicmd, certverify):
        yield firm
