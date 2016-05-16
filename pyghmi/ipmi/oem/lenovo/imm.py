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


def get_cached_data(ipmicmd, attribute):
    try:
        kv = getattr(ipmicmd.ipmi_session, attribute)
        if kv[1] > _monotonic_time() - 30:
            return kv[0]
    except AttributeError:
        return None


def get_web_session(ipmicmd, certverify, wc):
    if wc:
        return wc
    wc = get_imm_webclient(ipmicmd.bmc, certverify,
                           ipmicmd.ipmi_session.userid,
                           ipmicmd.ipmi_session.password)
    return wc


def fetch_agentless_firmware(ipmicmd, certverify):
    wc = None
    adapterdata = get_cached_data(ipmicmd, 'lenovo_cached_adapters')
    if not adapterdata:
        wc = get_web_session(ipmicmd, certverify, wc)
        if wc:
            adapterdata = wc.grab_json_response(
                '/designs/imm/dataproviders/imm_adapters.php')
            if adapterdata:
                ipmicmd.ipmi_session.lenovo_cached_adapters = (
                    adapterdata, _monotonic_time())
    if adapterdata and 'items' in adapterdata:
        for adata in adapterdata['items']:
            aname = adata['adapter.adapterName']
            donenames = set([])
            for fundata in adata['adapter.functions']:
                fdata = fundata.get('firmwares', ())
                for firm in fdata:
                    fname = firm['firmwareName'].rstrip()
                    if '.' in fname:
                        fname = firm['description'].rstrip()
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
                        try:
                            bdata['date'] = datetime.strptime(
                                firm['releaseDate'], '%m/%d/%Y')
                        except ValueError:
                            try:
                                bdata['date'] = datetime.strptime(
                                    firm['releaseDate'], '%m %d %Y')
                            except ValueError:
                                pass
                    yield ('{0} {1}'.format(aname, fname), bdata)
    storagedata = get_cached_data(ipmicmd, 'lenovo_cached_storage')
    if not storagedata:
        wc = get_web_session(ipmicmd, certverify, wc)
        if wc:
            storagedata = wc.grab_json_response(
                '/designs/imm/dataproviders/raid_alldevices.php')
            if storagedata:
                ipmicmd.ipmi_session.lenovo_cached_storage = (
                    storagedata, _monotonic_time())
    if storagedata and 'items' in storagedata:
        for adp in storagedata['items']:
            adpname = adp['storage.vpd.productName']
            if 'children' not in adp:
                adp['children'] = ()
            for diskent in adp['children']:
                bdata = {}
                diskname = '{0} Disk {1}'.format(
                    adpname,
                    diskent['storage.slotNo'])
                bdata['model'] = diskent['storage.vpd.productName'].rstrip()
                bdata['version'] = diskent['storage.firmwares'][0][
                    'versionStr']
                yield (diskname, bdata)
    if wc:
        wc.request('GET', '/data/logout')


def get_hw_inventory(ipmicmd, certverify):
    hwmap = hardware_inventory_map(ipmicmd, certverify)
    for key in hwmap:
        yield (key, hwmap[key])


def get_hw_descriptions(ipmicmd, certverify):
    hwmap = hardware_inventory_map(ipmicmd, certverify)
    for key in hwmap:
        yield key


def get_component_inventory(ipmicmd, certverify, compname):
    hwmap = hardware_inventory_map(ipmicmd, certverify)
    try:
        return hwmap[compname]
    except KeyError:
        return None


def hardware_inventory_map(ipmicmd, certverify):
    hwmap = get_cached_data(ipmicmd, 'lenovo_cached_hwmap')
    if hwmap:
        return hwmap
    hwmap = {}
    wc = None
    adapterdata = get_cached_data(ipmicmd, 'lenovo_cached_adapters')
    if not adapterdata:
        wc = get_web_session(ipmicmd, certverify, wc)
        if wc:
            adapterdata = wc.grab_json_response(
                '/designs/imm/dataproviders/imm_adapters.php')
            if adapterdata:
                ipmicmd.ipmi_session.lenovo_cached_adapters = (
                    adapterdata, _monotonic_time())
    if adapterdata and 'items' in adapterdata:
        for adata in adapterdata['items']:
            skipadapter = False
            if not adata['adapter.oobSupported']:
                continue
            aslot = None
            aname = adata['adapter.adapterName']
            clabel = adata['adapter.connectorLabel']
            if clabel == 'Unknown':
                continue
            if clabel != 'Onboard':
                aslot = adata['adapter.slotNo']
                if clabel == 'ML2':
                    clabel = 'ML2 (Slot {0})'.format(aslot)
                else:
                    clabel = 'Slot {0}'.format(aslot)
            bdata = {'location': clabel}
            for fundata in adata['adapter.functions']:
                bdata['pcislot'] = '{0:02x}:{1:02x}'.format(
                    fundata['generic.busNo'], fundata['generic.devNo'])
                serialdata = fundata.get('vpd.serialNo', None)
                if (serialdata and serialdata != 'N/A' and
                        '---' not in serialdata):
                    bdata['serial'] = serialdata
                partnum = fundata.get('vpd.partNo', None)
                if partnum and partnum != 'N/A':
                    bdata['partnumber'] = partnum
                if 'network.pPorts' in fundata:
                    for portinfo in fundata['network.pPorts']:
                        for lp in portinfo['logicalPorts']:
                            ma = lp['networkAddr']
                            ma = ':'.join(
                                [ma[i:i+2] for i in xrange(
                                    0, len(ma), 2)]).lower()
                            bdata['MAC Address {0}'.format(
                                portinfo['portIndex'])] = ma
                elif clabel == 'Onboard':  # skip the various onboard non-nic
                    skipadapter = True
            if not skipadapter:
                hwmap[aname] = bdata
        ipmicmd.ipmi_session.lenovo_cached_hwmap = (hwmap, _monotonic_time())
    return hwmap


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
    for firm in fetch_agentless_firmware(ipmicmd, certverify):
        yield firm
