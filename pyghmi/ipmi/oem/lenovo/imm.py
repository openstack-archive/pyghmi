# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2017 Lenovo
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
import errno
import json
import os.path
import pyghmi.constants as pygconst
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.oem.lenovo.energy as energy
import pyghmi.ipmi.private.session as ipmisession
import pyghmi.ipmi.private.util as util
import pyghmi.ipmi.sdr as sdr
import pyghmi.util.webclient as webclient
import random
import socket
import struct
import threading
import urllib
import weakref


def fixup_uuid(uuidprop):
    baduuid = ''.join(uuidprop.split())
    uuidprefix = (baduuid[:8], baduuid[8:12], baduuid[12:16])
    a = struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]).encode('hex')
    uuid = (a[:8], a[8:12], a[12:16], baduuid[16:20], baduuid[20:])
    return '-'.join(uuid).upper()


class FileUploader(threading.Thread):

    def __init__(self, webclient, url, filename, data):
        self.wc = webclient
        self.url = url
        self.filename = filename
        self.data = data
        super(FileUploader, self).__init__()

    def run(self):
        self.rsp = self.wc.upload(self.url, self.filename, self.data)


class IMMClient(object):
    logouturl = '/data/logout'
    bmcname = 'IMM'
    ADP_URL = '/designs/imm/dataproviders/imm_adapters.php'
    ADP_NAME = 'adapter.adapterName'
    ADP_FUN = 'adapter.functions'
    ADP_LABEL = 'adapter.connectorLabel'
    ADP_SLOTNO = 'adapter.slotNo'
    ADP_OOB = 'adapter.oobSupported'
    BUSNO = 'generic.busNo'
    PORTS = 'network.pPorts'
    DEVNO = 'generic.devNo'

    def __init__(self, ipmicmd):
        self.ipmicmd = weakref.proxy(ipmicmd)
        self.updating = False
        self.imm = ipmicmd.bmc
        self.adp_referer = 'https://{0}/designs/imm/index-console.php'.format(
            self.imm)
        self.username = ipmicmd.ipmi_session.userid
        self.password = ipmicmd.ipmi_session.password
        self._wc = None  # The webclient shall be initiated on demand
        self._energymanager = None
        self.datacache = {}

    @staticmethod
    def _parse_builddate(strval):
        try:
            return datetime.strptime(strval, '%Y/%m/%d %H:%M:%S')
        except ValueError:
            pass
        try:
            return datetime.strptime(strval, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
        try:
            return datetime.strptime(strval, '%Y/%m/%d')
        except ValueError:
            pass
        try:
            return datetime.strptime(strval, '%m/%d/%Y')
        except ValueError:
            pass
        try:
            return datetime.strptime(strval, '%Y-%m-%d')
        except ValueError:
            pass
        try:
            return datetime.strptime(strval, '%m %d %Y')
        except ValueError:
            pass
        return None

    @classmethod
    def parse_imm_buildinfo(cls, buildinfo):
        buildid = buildinfo[:9].rstrip(' \x00')
        bdt = ' '.join(buildinfo[9:].replace('\x00', ' ').split())
        bdate = cls._parse_builddate(bdt)
        return buildid, bdate

    @classmethod
    def datefromprop(cls, propstr):
        if propstr is None:
            return None
        return cls._parse_builddate(propstr)

    def get_property(self, propname):
        propname = propname.encode('utf-8')
        proplen = len(propname) | 0b10000000
        cmdlen = len(propname) + 1
        cdata = bytearray([0, 0, cmdlen, proplen]) + propname
        rsp = self.ipmicmd.xraw_command(netfn=0x3a, command=0xc4, data=cdata)
        rsp['data'] = bytearray(rsp['data'])
        if rsp['data'][0] != 0:
            return None
        propdata = rsp['data'][3:]  # second two bytes are size, don't need it
        if propdata[0] & 0b10000000:  # string, for now assume length valid
            return str(propdata[1:]).rstrip(' \x00')
        else:
            raise Exception('Unknown format for property: ' + repr(propdata))

    def get_webclient(self):
        cv = self.ipmicmd.certverify
        wc = webclient.SecureHTTPConnection(self.imm, 443, verifycallback=cv)
        try:
            wc.connect()
        except socket.error as se:
            if se.errno != errno.ECONNREFUSED:
                raise
            return None
        adata = urllib.urlencode({'user': self.username,
                                  'password': self.password,
                                  'SessionTimeout': 60
                                  })
        headers = {'Connection': 'keep-alive',
                   'Referer': 'https://{0}/designs/imm/index.php'.format(
                       self.imm),
                   'Content-Type': 'application/x-www-form-urlencoded'}
        wc.request('POST', '/data/login', adata, headers)
        rsp = wc.getresponse()
        if rsp.status == 200:
            rspdata = json.loads(rsp.read())
            if rspdata['authResult'] == '0' and rspdata['status'] == 'ok':
                if 'token2_name' in rspdata and 'token2_value' in rspdata:
                    wc.set_header(rspdata['token2_name'],
                                  rspdata['token2_value'])
                return wc

    @property
    def wc(self):
        if not self._wc:
            self._wc = self.get_webclient()
        return self._wc

    def fetch_grouped_properties(self, groupinfo):
        retdata = {}
        for keyval in groupinfo:
            retdata[keyval] = self.get_property(groupinfo[keyval])
            if keyval == 'date':
                retdata[keyval] = self.datefromprop(retdata[keyval])
        returnit = False
        for keyval in list(retdata):
            if retdata[keyval] in (None, ''):
                del retdata[keyval]
            else:
                returnit = True
        if returnit:
            return retdata

    def get_cached_data(self, attribute):
        try:
            kv = self.datacache[attribute]
            if kv[1] > util._monotonic_time() - 30:
                return kv[0]
        except KeyError:
            return None

    def attach_remote_media(self, url, user, password):
        url = url.replace(':', '\:')
        params = urllib.urlencode({
            'RP_VmAllocateMountUrl({0},{1},1,,)'.format(
                self.username, url): ''
        })
        result = self.wc.grab_json_response('/data?set', params)
        if result['return'] != 'Success':
            raise Exception(result['reason'])
        self.weblogout()

    def detach_remote_media(self):
        mnt = self.wc.grab_json_response(
            '/designs/imm/dataproviders/imm_rp_images.php')
        removeurls = []
        for item in mnt['items']:
            if 'urls' in item:
                for url in item['urls']:
                    removeurls.append(url['url'])
        for url in removeurls:
            url = url.replace(':', '\:')
            params = urllib.urlencode({
                'RP_VmAllocateUnMountUrl({0},{1},0,)'.format(
                    self.username, url): ''})
            result = self.wc.grab_json_response('/data?set', params)
            if result['return'] != 'Success':
                raise Exception(result['reason'])
        self.weblogout()

    def fetch_agentless_firmware(self):
        adapterdata = self.get_cached_data('lenovo_cached_adapters')
        if not adapterdata:
            if self.updating:
                raise pygexc.TemporaryError(
                    'Cannot read extended inventory during firmware update')
            if self.wc:
                adapterdata = self.wc.grab_json_response(
                    self.ADP_URL, referer=self.adp_referer)
                if adapterdata:
                    self.datacache['lenovo_cached_adapters'] = (
                        adapterdata, util._monotonic_time())
        if adapterdata and 'items' in adapterdata:
            for adata in adapterdata['items']:
                aname = adata[self.ADP_NAME]
                donenames = set([])
                for fundata in adata[self.ADP_FUN]:
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
                                bdata['date'] = self._parse_builddate(
                                    firm['releaseDate'])
                            except ValueError:
                                pass
                        yield ('{0} {1}'.format(aname, fname), bdata)
        storagedata = self.get_cached_data('lenovo_cached_storage')
        if not storagedata:
            if self.wc:
                storagedata = self.wc.grab_json_response(
                    '/designs/imm/dataproviders/raid_alldevices.php')
                if storagedata:
                    self.datacache['lenovo_cached_storage'] = (
                        storagedata, util._monotonic_time())
        if storagedata and 'items' in storagedata:
            for adp in storagedata['items']:
                if 'storage.vpd.productName' not in adp:
                    continue
                adpname = adp['storage.vpd.productName']
                if 'children' not in adp:
                    adp['children'] = ()
                for diskent in adp['children']:
                    bdata = {}
                    diskname = '{0} Disk {1}'.format(
                        adpname,
                        diskent['storage.slotNo'])
                    bdata['model'] = diskent[
                        'storage.vpd.productName'].rstrip()
                    bdata['version'] = diskent['storage.firmwares'][0][
                        'versionStr']
                    yield (diskname, bdata)
        self.weblogout()

    def get_hw_inventory(self):
        hwmap = self.hardware_inventory_map()
        for key in hwmap:
            yield (key, hwmap[key])

    def get_hw_descriptions(self):
        hwmap = self.hardware_inventory_map()
        for key in hwmap:
            yield key

    def get_component_inventory(self, compname):
        hwmap = self.hardware_inventory_map()
        try:
            return hwmap[compname]
        except KeyError:
            return None

    def get_oem_sensor_names(self, ipmicmd):
        if self._energymanager is None:
            self._energymanager = energy.EnergyManager(ipmicmd)
        return self._energymanager.supportedmeters

    def get_oem_sensor_descriptions(self, ipmicmd):
        return [{'name': x, 'type': 'Energy'
                 } for x in self.get_oem_sensor_names(ipmicmd)]

    def get_oem_sensor_reading(self, name, ipmicmd):
        if self._energymanager is None:
            self._energymanager = energy.EnergyManager(ipmicmd)
        if name == 'AC Energy':
            kwh = self._energymanager.get_ac_energy(ipmicmd)
        elif name == 'DC Energy':
            kwh = self._energymanager.get_dc_energy(ipmicmd)
        else:
            raise pygexc.UnsupportedFunctionality('No sunch sensor ' + name)
        return sdr.SensorReading({'name': name, 'imprecision': None,
                                  'value': kwh, 'states': [],
                                  'state_ids': [],
                                  'health': pygconst.Health.Ok,
                                  'type': 'Energy'}, 'kWh')

    def weblogout(self):
        if self._wc:
            try:
                self._wc.grab_json_response(self.logouturl)
            except Exception:
                pass
            self._wc = None

    def hardware_inventory_map(self):
        hwmap = self.get_cached_data('lenovo_cached_hwmap')
        if hwmap:
            return hwmap
        hwmap = {}
        enclosureuuid = self.get_property('/v2/ibmc/smm/chassis/uuid')
        if enclosureuuid:
            hwmap['Enclosure'] = {'UUID': fixup_uuid(enclosureuuid)}
        adapterdata = self.get_cached_data('lenovo_cached_adapters')
        if not adapterdata:
            if self.updating:
                raise pygexc.TemporaryError(
                    'Cannot read extended inventory during firmware update')
            if self.wc:
                adapterdata = self.wc.grab_json_response(
                    self.ADP_URL, referer=self.adp_referer)
                if adapterdata:
                    self.datacache['lenovo_cached_adapters'] = (
                        adapterdata, util._monotonic_time())
        if adapterdata and 'items' in adapterdata:
            for adata in adapterdata['items']:
                skipadapter = False
                if not adata[self.ADP_OOB]:
                    continue
                aname = adata[self.ADP_NAME]
                clabel = adata[self.ADP_LABEL]
                if clabel == 'Unknown':
                    continue
                if clabel != 'Onboard':
                    aslot = adata[self.ADP_SLOTNO]
                    if clabel == 'ML2':
                        clabel = 'ML2 (Slot {0})'.format(aslot)
                    else:
                        clabel = 'Slot {0}'.format(aslot)
                bdata = {'location': clabel}
                for fundata in adata[self.ADP_FUN]:
                    bdata['pcislot'] = '{0:02x}:{1:02x}'.format(
                        fundata[self.BUSNO], fundata[self.DEVNO])
                    serialdata = fundata.get('vpd.serialNo', None)
                    if (serialdata and serialdata != 'N/A' and
                            '---' not in serialdata):
                        bdata['serial'] = serialdata
                    partnum = fundata.get('vpd.partNo', None)
                    if partnum and partnum != 'N/A':
                        bdata['partnumber'] = partnum
                    if self.PORTS in fundata:
                        for portinfo in fundata[self.PORTS]:
                            for lp in portinfo['logicalPorts']:
                                ma = lp['networkAddr']
                                ma = ':'.join(
                                    [ma[i:i+2] for i in range(
                                        0, len(ma), 2)]).lower()
                                bdata['MAC Address {0}'.format(
                                    portinfo['portIndex'])] = ma
                    elif clabel == 'Onboard':  # skip the various non-nic
                        skipadapter = True
                if not skipadapter:
                    hwmap[aname] = bdata
            self.datacache['lenovo_cached_hwmap'] = (hwmap,
                                                     util._monotonic_time())
        self.weblogout()
        return hwmap

    def get_firmware_inventory(self, bmcver):
        # First we fetch the system firmware found in imm properties
        # then check for agentless, if agentless, get adapter info using
        # https, using the caller TLS verification scheme
        rsp = self.ipmicmd.xraw_command(netfn=0x3a, command=0x50)
        immverdata = self.parse_imm_buildinfo(rsp['data'])
        bdata = {
            'version': bmcver, 'build': immverdata[0], 'date': immverdata[1]}
        yield (self.bmcname, bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/ibmc/dm/fw/imm2/backup_build_id',
            'version': '/v2/ibmc/dm/fw/imm2/backup_build_version',
            'date': '/v2/ibmc/dm/fw/imm2/backup_build_date'})
        if bdata:
            yield ('{0} Backup'.format(self.bmcname), bdata)
            bdata = self.fetch_grouped_properties({
                'build': '/v2/ibmc/trusted_buildid',
            })
        if bdata:
            yield ('{0} Trusted Image'.format(self.bmcname), bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/bios/build_id',
            'version': '/v2/bios/build_version',
            'date': '/v2/bios/build_date'})
        if bdata:
            yield ('UEFI', bdata)
        else:
            yield ('UEFI', {'version': 'unknown'})
        bdata = self.fetch_grouped_properties({
            'build': '/v2/ibmc/dm/fw/bios/backup_build_id',
            'version': '/v2/ibmc/dm/fw/bios/backup_build_version'})
        if bdata:
            yield ('UEFI Backup', bdata)
        # Note that the next pending could be pending for either primary
        # or backup, so can't promise where it will go
        bdata = self.fetch_grouped_properties({
            'build': '/v2/bios/pending_build_id'})
        if bdata:
            yield ('UEFI Pending Update', bdata)
        try:
            fpga = self.ipmicmd.xraw_command(netfn=0x3a, command=0x6b,
                                             data=(0,))
            fpga = '{0}.{1}.{2}'.format(*[ord(x) for x in fpga['data']])
            yield ('FPGA', {'version': fpga})
        except pygexc.IpmiException as ie:
            if ie.ipmicode != 193:
                raise
        for firm in self.fetch_agentless_firmware():
            yield firm


class XCCClient(IMMClient):
    logouturl = '/api/providers/logout'
    bmcname = 'XCC'
    ADP_URL = '/api/dataset/imm_adapters?params=pci_GetAdapters'
    ADP_NAME = 'adapterName'
    ADP_FUN = 'functions'
    ADP_LABEL = 'connectorLabel'
    ADP_SLOTNO = 'slotNo'
    ADP_OOB = 'oobSupported'
    BUSNO = 'generic_busNo'
    PORTS = 'network_pPorts'
    DEVNO = 'generic_devNo'

    def get_webclient(self):
        cv = self.ipmicmd.certverify
        wc = webclient.SecureHTTPConnection(self.imm, 443, verifycallback=cv)
        try:
            wc.connect()
        except socket.error as se:
            if se.errno != errno.ECONNREFUSED:
                raise
            return None
        adata = json.dumps({'username': self.username,
                            'password': self.password
                            })
        headers = {'Connection': 'keep-alive',
                   'Content-Type': 'application/json'}
        wc.request('POST', '/api/login', adata, headers)
        rsp = wc.getresponse()
        if rsp.status == 200:
            rspdata = json.loads(rsp.read())
            wc.set_header('Content-Type', 'application/json')
            wc.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
            if '_csrf_token' in wc.cookies:
                wc.set_header('X-XSRF-TOKEN', wc.cookies['_csrf_token'])
            return wc

    def attach_remote_media(self, url, user, password):
        proto, host, path = util.urlsplit(url)
        if proto == 'smb':
            proto = 'cifs'
        rq = {'Option': '', 'Domain': '', 'Write': 0}
        # nfs == 1, cifs == 0
        if proto == 'nfs':
            rq['Protocol'] = 1
            rq['Url'] = '{0}:{1}'.format(host, path)
        elif proto == 'cifs':
            rq['Protocol'] = 0
            rq['Credential'] = '{0}:{1}'.format(user, password)
            rq['Url'] = '//{0}{1}'.format(host, path)
        elif proto in ('http', 'https'):
            rq['Protocol'] = 7
            rq['Url'] = url
        else:
            raise Exception('TODO')
        rt = self.wc.grab_json_response('/api/providers/rp_vm_remote_connect',
                                        json.dumps(rq))
        if 'return' not in rt or rt['return'] != 0:
            raise Exception('Unhandled return: ' + repr(rt))
        rt = self.wc.grab_json_response('/api/providers/rp_vm_remote_mountall',
                                        '{}')
        if 'return' not in rt or rt['return'] != 0:
            raise Exception('Unhandled return: ' + repr(rt))

    def get_firmware_inventory(self, bmcver):
        # First we fetch the system firmware found in imm properties
        # then check for agentless, if agentless, get adapter info using
        # https, using the caller TLS verification scheme
        rsp = self.ipmicmd.xraw_command(netfn=0x3a, command=0x50)
        immverdata = self.parse_imm_buildinfo(rsp['data'])
        bdata = {
            'version': bmcver, 'build': immverdata[0], 'date': immverdata[1]}
        yield (self.bmcname, bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/ibmc/dm/fw/imm3/backup_pending_build_id',
            'version': '/v2/ibmc/dm/fw/imm3/backup_pending_build_version',
            'date': '/v2/ibmc/dm/fw/imm3/backup_pending_build_date'})
        if bdata:
            yield ('{0} Backup'.format(self.bmcname), bdata)
        else:
            bdata = self.fetch_grouped_properties({
                'build': '/v2/ibmc/dm/fw/imm3/backup_build_id',
                'version': '/v2/ibmc/dm/fw/imm3/backup_build_version',
                'date': '/v2/ibmc/dm/fw/imm3/backup_build_date'})
            if bdata:
                yield ('{0} Backup'.format(self.bmcname), bdata)
                bdata = self.fetch_grouped_properties({
                    'build': '/v2/ibmc/trusted_buildid',
                })
        if bdata:
            bdata = self.fetch_grouped_properties({
                'build': '/v2/ibmc/trusted_buildid',
            })
        if bdata:
            yield ('{0} Trusted Image'.format(self.bmcname), bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/ibmc/dm/fw/imm3/primary_pending_build_id',
            'version': '/v2/ibmc/dm/fw/imm3/primary_pending_build_version',
            'date': '/v2/ibmc/dm/fw/imm3/primary_pending_build_date'})
        if bdata:
            yield ('{0} Pending Update'.format(self.bmcname), bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/bios/build_id',
            'version': '/v2/bios/build_version',
            'date': '/v2/bios/build_date'})
        if bdata:
            yield ('UEFI', bdata)
        # Note that the next pending could be pending for either primary
        # or backup, so can't promise where it will go
        bdata = self.fetch_grouped_properties({
            'build': '/v2/bios/pending_build_id'})
        if bdata:
            yield ('UEFI Pending Update', bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/tdm/build_id',
            'version': '/v2/tdm/build_version',
            'date': '/v2/tdm/build_date'})
        if bdata:
            yield ('LXPM', bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/drvwn/build_id',
            'version': '/v2/drvwn/build_version',
            'date': '/v2/drvwn/build_date',
        })
        if bdata:
            yield ('LXPM Windows Driver Bundle', bdata)
        bdata = self.fetch_grouped_properties({
            'build': '/v2/drvln/build_id',
            'version': '/v2/drvln/build_version',
            'date': '/v2/drvln/build_date',
        })
        if bdata:
            yield ('LXPM Linux Driver Bundle', bdata)
        try:
            fpga = self.ipmicmd.xraw_command(netfn=0x3a, command=0x6b,
                                             data=(0,))
            fpga = '{0}.{1}.{2}'.format(*[ord(x) for x in fpga['data']])
            yield ('FPGA', {'version': fpga})
        except pygexc.IpmiException as ie:
            if ie.ipmicode != 193:
                raise
        for firm in self.fetch_agentless_firmware():
            yield firm

    def detach_remote_media(self):
        rt = self.wc.grab_json_response('/api/providers/rp_vm_remote_getdisk')
        if 'items' in rt:
            slots = []
            for mount in rt['items']:
                slots.append(mount['slotId'])
            for slot in slots:
                rt = self.wc.grab_json_response(
                    '/api/providers/rp_vm_remote_unmount',
                    json.dumps({'Slot': slot}))
                if 'return' not in rt or rt['return'] != 0:
                    raise Exception("Unrecognized return: " + repr(rt))

    def update_firmware(self, filename, data=None, progress=None, bank=None):
        result = None
        if self.updating:
            raise pygexc.TemporaryError('Cannot run multiple updates to same '
                                        'target concurrently')
        self.updating = True
        try:
            result = self.update_firmware_backend(filename, data, progress,
                                                  bank)
        except Exception:
            self.updating = False
            self._refresh_token()
            self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
                {'UPD_WebCancel': 1}))
            self.weblogout()
            raise
        self.updating = False
        self.weblogout()
        return result

    def _refresh_token(self):
        self.wc.grab_json_response('/api/providers/identity')
        if '_csrf_token' in self.wc.cookies:
            self.wc.set_header('X-XSRF-TOKEN', self.wc.cookies['_csrf_token'])

    def update_firmware_backend(self, filename, data=None, progress=None,
                                bank=None):
        self.weblogout()
        self._refresh_token()
        rsv = self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
            {'UPD_WebReserve': 1}))
        if rsv['return'] == 103:
            raise Exception('Update already in progress')
        if rsv['return'] != 0:
            raise Exception('Unexpected return to reservation: ' + repr(rsv))
        xid = random.randint(0, 1000000000)
        uploadthread = FileUploader(self.wc,
                                    '/upload?X-Progress-ID={0}'.format(xid),
                                    filename, data)
        uploadthread.start()
        uploadstate = None
        while uploadthread.isAlive():
            uploadthread.join(3)
            rsp = self.wc.grab_json_response(
                '/upload/progress?X-Progress-ID={0}'.format(xid))
            if rsp['state'] == 'uploading':
                progress({'phase': 'upload',
                          'progress': 100.0 * rsp['received'] / rsp['size']})
            elif rsp['state'] != 'done':
                raise Exception('Unexpected result:' + repr(rsp))
            uploadstate = rsp['state']
            self._refresh_token()
        while uploadstate != 'done':
            rsp = self.wc.grab_json_response(
                '/upload/progress?X-Progress-ID={0}'.format(xid))
            uploadstate = rsp['state']
            self._refresh_token()
        rsp = json.loads(uploadthread.rsp)
        if rsp['items'][0]['name'] != os.path.basename(filename):
            raise Exception('Unexpected response: ' + repr(rsp))
        progress({'phase': 'validating',
                  'progress': 0.0})
        ipmisession.Session.pause(3)
        # aggressive timing can cause the next call to occasionally
        # return 25 and fail
        self._refresh_token()
        rsp = self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
            {'UPD_WebSetFileName': rsp['items'][0]['path']}))
        if rsp['return'] == 25:
            raise Exception('Temporory error validating update, try again')
        if rsp['return'] != 0:
            raise Exception('Unexpected return to set filename: ' + repr(rsp))
        progress({'phase': 'validating',
                  'progress': 25.0})
        rsp = self.wc.grab_json_response('/api/providers/fwupdate', json.dumps(
            {'UPD_WebVerifyUploadFile': 1}))
        if rsp['return'] == 115:
            raise Exception('Update image not intended for this system')
        if rsp['return'] != 0:
            raise Exception('Unexpected return to verify: ' + repr(rsp))
        progress({'phase': 'validating',
                  'progress': 99.0})
        self._refresh_token()
        rsp = self.wc.grab_json_response('/api/dataset/imm_firmware_success')
        if len(rsp['items']) != 1:
            raise Exception('Unexpected result: ' + repr(rsp))
        firmtype = rsp['items'][0]['firmware_type']
        if firmtype not in (
                'TDM', 'WINDOWS DRIV', 'LINUX DRIVER', 'UEFI', 'IMM'):
            # adapter firmware
            webid = rsp['items'][0]['webfile_build_id']
            locations = webid[webid.find('[')+1:webid.find(']')]
            locations = locations.split(':')
            if len(locations) > 1:
                raise Exception("Multiple of the same adapter not supported")
            validselector = locations[0].replace('#', '-')
            rsp = self.wc.grab_json_response(
                '/api/function/adapter_update?params=pci_GetAdapterListAndFW')
            for adpitem in rsp['items']:
                selector = '{0}-{1}'.format(adpitem['location'],
                                            adpitem['slotNo'])
                if selector == validselector:
                    break
            else:
                raise Exception('Could not find matching adapter for update')
            rsp = self.wc.grab_json_response('/api/function', json.dumps(
                {'pci_SetOOBFWSlots': selector}))
            if rsp['return'] != 0:
                raise Exception(
                    'Unexpected result from PCI select: ' + repr(rsp))
        else:
            rsp = self.wc.grab_json_response(
                '/api/dataset/imm_firmware_update')
            if rsp['items'][0]['upgrades'][0]['id'] != 1:
                raise Exception('Unexpected answer: ' + repr(rsp))
        self._refresh_token()
        progress({'phase': 'apply',
                  'progress': 0.0})
        if bank in ('primary', None):
            rsp = self.wc.grab_json_response(
                '/api/providers/fwupdate', json.dumps(
                    {'UPD_WebStartDefaultAction': 1}))
        elif bank == 'backup':
            rsp = self.wc.grab_json_response(
                '/api/providers/fwupdate', json.dumps(
                    {'UPD_WebStartOptionalAction': 2}))

        if rsp['return'] != 0:
            raise Exception('Unexpected result starting update: ' +
                            rsp['return'])
        complete = False
        while not complete:
            ipmisession.Session.pause(3)
            rsp = self.wc.grab_json_response(
                '/api/dataset/imm_firmware_progress')
            progress({'phase': 'apply',
                      'progress': rsp['items'][0]['action_percent_complete']})
            if rsp['items'][0]['action_state'] == 'Idle':
                complete = True
                break
            if rsp['items'][0]['action_state'] == 'Complete OK':
                complete = True
                if rsp['items'][0]['action_status'] != 0:
                    raise Exception('Unexpected failure: ' + repr(rsp))
                break
            if (rsp['items'][0]['action_state'] == 'In Progress' and
                    rsp['items'][0]['action_status'] == 2):
                raise Exception('Unexpected failure: ' + repr(rsp))
            if rsp['items'][0]['action_state'] != 'In Progress':
                raise Exception(
                    'Unknown condition waiting for '
                    'firmware update: ' + repr(rsp))
        if bank == 'backup':
            return 'complete'
        return 'pending'
