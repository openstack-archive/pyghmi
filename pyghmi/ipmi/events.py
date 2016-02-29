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

# __author__ = 'jjohnson2@lenovo.com'

import pyghmi.constants as pygconst
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.private.constants as ipmiconst
import struct
import time


psucfg_errors = {
    0: 'Vendor mismatch',
    1: 'Revision mismatch',
    2: 'Processor missing',  # e.g. pluggable CPU VRMs...
    3: 'Insufficient power',
    4: 'Voltage mismatch',
}

firmware_progress = {
    0: 'Unspecified',
    1: 'Memory initialization',
    2: 'Disk initialization',
    3: 'Non-primary Processor initialization',
    4: 'User authentication',
    5: 'Entering setup',
    6: 'USB initialization',
    7: 'PCI initialization',
    8: 'Option ROM initialization',
    9: 'Video initialization',
    0xa: 'Cache initialization',
    0xb: 'SMBus initialization',
    0xc: 'Keyboard initialization',
    0xd: 'Embedded controller initialization',
    0xe: 'Docking station attachment',
    0xf: 'Docking station enabled',
    0x10: 'Docking station ejection',
    0x11: 'Docking station disabled',
    0x12: 'Waking OS',
    0x13: 'Starting OS boot',
    0x14: 'Baseboard initialization',
    0x16: 'Floppy initialization',
    0x17: 'Keyboard test',
    0x18: 'Pointing device test',
    0x19: 'Primary processor initialization',
}

firmware_errors = {
    0: 'Unspecified',
    1: 'No memory installed',
    2: 'All memory failed',
    3: 'Unrecoverable disk failure',
    4: 'Unrecoverable board failure',
    5: 'Unrecoverable diskette failure',
    6: 'Unrecoverable storage controller failure',
    7: 'Unrecoverable keyboard failure',  # Keyboard error, press
                                          # any key to continue..
    8: 'Removable boot media not found',
    9: 'Video adapter failure',
    0xa: 'No video device',
    0xb: 'Firmware corruption detected',
    0xc: 'CPU voltage mismatch',
    0xd: 'CPU speed mismatch',
}

auxlog_actions = {
    0: 'entry added',
    1: 'entry added (could not map to standard)',
    2: 'entry added with corresponding standard events',
    3: 'log cleared',
    4: 'log disabled',
    5: 'log enabled',
}

restart_causes = {
    0: 'Unknown',
    1: 'Remote request',
    2: 'Reset button',
    3: 'Power button',
    4: 'Watchdog',
    5: 'OEM',
    6: 'Power restored',
    7: 'Power restored',
    8: 'Reset due to event',
    9: 'Cycle due to event',
    0xa: 'OS reset',
    0xb: 'Timer wake',
}

slot_types = {
    0: 'PCI',
    1: 'Drive Array',
    2: 'External connector',
    3: 'Docking',
    4: 'Other',
    5: 'Entity ID',
    6: 'AdvancedTCA',
    7: 'Memory',
    8: 'Fan',
    9: 'PCIe',
    10: 'SCSI',
    11: 'SATA/SAS',
}

power_states = {
    0: 'S0',
    1: 'S1',
    2: 'S2',
    3: 'S3',
    4: 'S4',
    5: 'S5',
    6: 'S4 or S5',
    7: 'G3',
    8: 'S1, S2, or S3',
    9: 'G1',
    0xa: 'S5',
    0xb: 'on',
    0xc: 'off',
}

watchdog_boot_phases = {
    1: 'Firmware',
    2: 'Firmware',
    3: 'OS Load',
    4: 'OS',
    5: 'OEM',
}

version_changes = {
    1: 'Device ID',
    2: 'Management controller firmware',
    3: 'Management controller revision',
    4: 'Management conroller manufacturer',
    5: 'IPMI version',
    6: 'Management controller firmware',
    7: 'Management controller boot block',
    8: 'Management controller firmware',
    9: 'System Firmware (UEFI/BIOS)',
    0xa: 'SMBIOS',
    0xb: 'OS',
    0xc: 'OS Loader',
    0xd: 'Diagnostics',
    0xe: 'Management agent',
    0xf: 'Management application',
    0x10: 'Management middleware',
    0x11: 'FPGA',
    0x12: 'FRU',
    0x13: 'FRU',
    0x14: 'Equivalent FRU',
    0x15: 'Updated FRU',
    0x16: 'Older FRU',
    0x17: 'Hardware (switch/jumper)',
}

fru_states = {
    0: 'Normal',
    1: 'Externally requested',
    2: 'Latch',
    3: 'Hot swap',
    4: 'Internal action',
    5: 'Lost communication',
    6: 'Lost communication',
    7: 'Unexpected removal',
    8: 'Operator',
    9: 'Unable to compute IPMB address',
    0xa: 'Unexpected deactivation',
}


def decode_eventdata(sensor_type, offset, eventdata, sdr):
    """Decode extra event data from an alert or log

    Provide a textual summary of eventdata per descriptions in
    Table 42-3 of the specification.  This is for sensor specific
    offset events only.

    :param sensor_type: The sensor type number from the event
    :param offset:  Sensor specific offset
    :param eventdata: The three bytes from the log or alert
    """
    if sensor_type == 5 and offset == 4:  # link loss, indicates which port
        return 'Port {0}'.format(eventdata[1])
    elif sensor_type == 8 and offset == 6:  # PSU cfg error
        errtype = eventdata[2] & 0b1111
        return psucfg_errors.get(errtype, 'Unknown')
    elif sensor_type == 0xc and offset == 8:  # Memory spare
        return 'Module {0}'.format(eventdata[2])
    elif sensor_type == 0xf:
        if offset == 0:  # firmware error
            return firmware_errors.get(eventdata[1], 'Unknown')
        elif offset in (1, 2):
            return firmware_progress.get(eventdata[1], 'Unknown')
    elif sensor_type == 0x10:
        if offset == 0:  # Correctable error logging on a specific memory part
            return 'Module {0}'.format(eventdata[1])
        elif offset == 1:
            return 'Reading type {0:02X}h, offset {1:02X}h'.format(
                eventdata[1], eventdata[2] & 0b1111)
        elif offset == 5:
            return '{0}%'.format(eventdata[2])
        elif offset == 6:
            return 'Processor {0}'.format(eventdata[1])
    elif sensor_type == 0x12:
        if offset == 3:
            action = (eventdata[1] & 0b1111000) >> 4
            return auxlog_actions.get(action, 'Unknown')
        elif offset == 4:
            sysactions = []
            if eventdata[1] & 0b1 << 5:
                sysactions.append('NMI')
            if eventdata[1] & 0b1 << 4:
                sysactions.append('OEM action')
            if eventdata[1] & 0b1 << 3:
                sysactions.append('Power Cycle')
            if eventdata[1] & 0b1 << 2:
                sysactions.append('Reset')
            if eventdata[1] & 0b1 << 1:
                sysactions.append('Power Down')
            if eventdata[1] & 0b1:
                sysactions.append('Alert')
            return ','.join(sysactions)
        elif offset == 5:  # Clock change event, either before or after
            if eventdata[1] & 0b10000000:
                return 'After'
            else:
                return 'Before'
    elif sensor_type == 0x19 and offset == 0:
        return 'Requested {0] while {1}'.format(eventdata[1], eventdata[2])
    elif sensor_type == 0x1d and offset == 7:
        return restart_causes.get(eventdata[1], 'Unknown')
    elif sensor_type == 0x21 and offset == 0x9:
        return '{0} {1}'.format(slot_types.get(eventdata[1], 'Unknown'),
                                eventdata[2])

    elif sensor_type == 0x23:
        phase = eventdata[1] & 0b1111
        return watchdog_boot_phases.get(phase, 'Unknown')
    elif sensor_type == 0x28:
        if offset == 4:
            return 'Sensor {0}'.format(eventdata[1])
        elif offset == 5:
            islogical = (eventdata[1] & 0b10000000)
            if islogical:
                if eventdata[2] in sdr.fru:
                    return sdr.fru[eventdata[2]].fru_name
                else:
                    return 'FRU {0}'.format(eventdata[2])
    elif sensor_type == 0x2a and offset == 3:
        return 'User {0}'.format(eventdata[1])
    elif sensor_type == 0x2b:
        return version_changes.get(eventdata[1], 'Unknown')
    elif sensor_type == 0x2c:
        cause = (eventdata[1] & 0b11110000) >> 4
        cause = fru_states.get(cause, 'Unknown')
        oldstate = eventdata[1] & 0b1111
        if oldstate != offset:
            try:
                cause += '(change from {0})'.format(
                    ipmiconst.sensor_type_offsets[0x2c][oldstate]['desc'])
            except KeyError:
                pass


def _fix_sel_time(records, ipmicmd):
    timefetched = False
    rsp = None
    while not timefetched:
        try:
            rsp = ipmicmd.xraw_command(netfn=0xa, command=0x48)
            timefetched = True
        except pygexc.IpmiException as pi:
            if pi.ipmicode == 0x81:
                continue
            raise
    # The specification declares an epoch and all that, but we really don't
    # care.  We instead just focus on differences from the 'present'
    nowtime = struct.unpack_from('<I', rsp['data'])[0]
    correctednowtime = nowtime
    if nowtime < 0x20000000:
        correctearly = True
        inpreinit = True
    else:
        correctearly = False
        inpreinit = False
    newtimestamp = 0
    lasttimestamp = None
    trimindexes = []
    for index in reversed(xrange(len(records))):
        record = records[index]
        if 'timecode' not in record or record['timecode'] == 0xffffffff:
            continue
        if ('event' in record and record['event'] == 'Clock time change' and
                record['event_data'] == 'After'):
            newtimestamp = record['timecode']
            trimindexes.append(index)
        elif ('event' in record and record['event'] == 'Clock time change' and
                record['event_data'] == 'Before'):
            if newtimestamp:
                if record['timecode'] < 0x20000000:
                    correctearly = True
                    nowtime = correctednowtime
                correctednowtime += newtimestamp - record['timecode']
                newtimestamp = 0
            trimindexes.append(index)
        else:
            # clean up after potentially broken time sync pairs
            newtimestamp = 0
            if record['timecode'] < 0x20000000:  # uptime timestamp
                if not correctearly:
                    correctednowtime = nowtime
                    continue
                if (lasttimestamp is not None and
                        record['timecode'] > lasttimestamp):
                    # Time has gone backwards in pre-init, no hope for
                    # accurate time
                    correctearly = False
                    correctednowtime = nowtime
                    continue
                inpreinit = True
                lasttimestamp = record['timecode']
                age = correctednowtime - record['timecode']
                record['timestamp'] = time.strftime(
                    '%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - age))
            else:
                # We are in 'normal' time, assume we cannot go to
                # pre-init time and do corrections unless time sync events
                # guide us in safely
                if inpreinit:
                    inpreinit = False
                    # We were in pre-init, now in real time, reset the
                    # time correction factor to the last stored
                    # 'wall clock' correction
                    correctednowtime = nowtime
                correctearly = False
                if correctednowtime < 0x20000000:
                    # We can't correct time when the correction factor is
                    # rooted in a pre-init timestamp, just convert
                    record['timestamp'] = time.strftime(
                        '%Y-%m-%dT%H:%M:%S', time.localtime(
                            record['timecode']))
                else:
                    age = correctednowtime - record['timecode']
                    record['timestamp'] = time.strftime(
                        '%Y-%m-%dT%H:%M:%S', time.localtime(
                            time.time() - age))
    for index in trimindexes:
        del records[index]


class EventHandler(object):
    """IPMI Event Processor

    This class provides facilities for processing alerts and event log
    data.  This can be used to aid in pulling historical event data
    from a BMC or as part of a trap handler to translate the traps into
    manageable data.

    :param sdr: An SDR object (per pyghmi.ipmi.sdr) matching the target BMC SDR
    """
    def __init__(self, sdr, ipmicmd):
        self._sdr = sdr
        self._ipmicmd = ipmicmd

    def _populate_event(self, deassertion, event, event_data, event_type,
                        sensor_type, sensorid):
        event['component_id'] = sensorid
        try:
            event['component'] = self._sdr.sensors[sensorid].name
        except KeyError:
            if sensorid == 0:
                event['component'] = None
            else:
                event['component'] = 'Sensor {0}'.format(sensorid)
        event['deassertion'] = deassertion
        event['event_data_bytes'] = event_data
        byte2type = (event_data[0] & 0b11000000) >> 6
        byte3type = (event_data[0] & 0b110000) >> 4
        if byte2type == 1:
            event['triggered_value'] = event_data[1]
        evtoffset = event_data[0] & 0b1111
        event['event_type_byte'] = event_type
        if event_type <= 0xc:
            event['component_type_id'] = sensor_type
            event['event_id'] = '{0}.{1}'.format(event_type, evtoffset)
            # use generic offset decode for event description
            event['component_type'] = ipmiconst.sensor_type_codes.get(
                sensor_type, '')
            evreading = ipmiconst.generic_type_offsets.get(
                event_type, {}).get(evtoffset, {})
            if event['deassertion']:
                event['event'] = evreading.get('deassertion_desc', '')
                event['severity'] = evreading.get(
                    'deassertion_severity', pygconst.Health.Ok)
            else:
                event['event'] = evreading.get('desc', '')
                event['severity'] = evreading.get(
                    'severity', pygconst.Health.Ok)
        elif event_type == 0x6f:
            event['component_type_id'] = sensor_type
            event['event_id'] = '{0}.{1}'.format(event_type, evtoffset)
            event['component_type'] = ipmiconst.sensor_type_codes.get(
                sensor_type, '')
            evreading = ipmiconst.sensor_type_offsets.get(
                sensor_type, {}).get(evtoffset, {})
            if event['deassertion']:
                event['event'] = evreading.get('deassertion_desc', '')
                event['severity'] = evreading.get(
                    'deassertion_severity', pygconst.Health.Ok)
            else:
                event['event'] = evreading.get('desc', '')
                event['severity'] = evreading.get(
                    'severity', pygconst.Health.Ok)
        if event_type == 1:  # threshold
            if byte3type == 1:
                event['threshold_value'] = event_data[2]
        if 3 in (byte2type, byte3type) or event_type == 0x6f:
            # sensor specific decode, see sdr module...
            # 2 - 0xc: generic discrete, 0x6f, sensor specific
            additionaldata = decode_eventdata(
                sensor_type, evtoffset, event_data, self._sdr)
            if additionaldata:
                event['event_data'] = additionaldata

    def decode_pet(self, specifictrap, petdata):
        if isinstance(specifictrap, int):
            specifictrap = struct.unpack('4B', struct.pack('>I', specifictrap))
        if len(specifictrap) != 4:
            raise pygexc.InvalidParameterValue(
                'specifictrap should be integer number or 4 byte array')
        specifictrap = bytearray(specifictrap)
        sensor_type = specifictrap[1]
        event_type = specifictrap[2]
        # Event Offset is in first event data byte, so no need to fetch it here
        # evtoffset = specifictrap[3] & 0b1111
        deassertion = (specifictrap[3] & 0b10000000) == 0b10000000
        # alertseverity = petdata[26]
        sensorid = petdata[28]
        event_data = petdata[31:34]
        event = {}
        seqnum = struct.unpack_from('>H', buffer(petdata[16:18]))[0]
        ltimestamp = struct.unpack_from('>I', buffer(petdata[18:22]))[0]
        petack = bytearray(struct.pack('<HIBBBBBB', seqnum, ltimestamp,
                                       petdata[25], petdata[27], sensorid,
                                       *event_data))
        try:
            self._ipmicmd.xraw_command(netfn=4, command=0x17, data=petack)
        except pygexc.IpmiException:  # Ignore failure to ack for now
            pass
        self._populate_event(deassertion, event, event_data, event_type,
                             sensor_type, sensorid)
        event['timecode'] = ltimestamp
        _fix_sel_time((event,), self._ipmicmd)
        return event

    def _decode_standard_event(self, eventdata, event):
        # Ignore the generator id for now..
        if eventdata[2] not in (3, 4):
            raise pygexc.PyghmiException(
                'Unrecognized Event message version {0}'.format(eventdata[2]))
        sensor_type = eventdata[3]
        sensorid = eventdata[4]
        event_data = eventdata[6:]
        deassertion = (eventdata[5] & 0b10000000 == 0b10000000)
        event_type = eventdata[5] & 0b1111111
        self._populate_event(deassertion, event, event_data, event_type,
                             sensor_type, sensorid)

    def _sel_decode(self, origselentry):
        selentry = bytearray(origselentry)
        event = {}
        event['record_id'] = struct.unpack_from('<H', origselentry[:2])[0]
        if selentry[2] == 2 or (0xc0 <= selentry[2] <= 0xdf):
            # Either standard, or at least the timestamp is standard
            event['timecode'] = struct.unpack_from('<I', buffer(selentry[3:7])
                                                   )[0]
        if selentry[2] == 2:  # ipmi defined standard format
            self._decode_standard_event(selentry[7:], event)
        elif 0xc0 <= selentry[2] <= 0xdf:
            event['oemid'] = selentry[7:10]
            event['oemdata'] = selentry[10:]
        elif selentry[2] >= 0xe0:
            # In this class of OEM message, all bytes are OEM, interpretation
            # is wholly left up to the OEM layer, using the OEM ID of the BMC
            event['oemdata'] = selentry[3:]
        self._ipmicmd._oem.process_event(event, self._ipmicmd, selentry)
        if 'event_type_byte' in event:
            del event['event_type_byte']
        if 'event_data_bytes' in event:
            del event['event_data_bytes']
        return event

    def _fetch_entries(self, ipmicmd, startat, targetlist, rsvid=0):
        curr = startat
        endat = curr
        while curr != 0xffff:
            endat = curr
            reqdata = bytearray(struct.pack('<HHH', rsvid, curr, 0xff00))
            try:
                rsp = ipmicmd.xraw_command(
                    netfn=0xa, command=0x43, data=reqdata)
            except pygexc.IpmiException as pi:
                if pi.ipmicode == 203:
                    break
            curr = struct.unpack_from('<H', buffer(rsp['data'][:2]))[0]
            targetlist.append(self._sel_decode(rsp['data'][2:]))
        return endat

    def fetch_sel(self, ipmicmd, clear=False):
        """Fetch SEL entries

        Return an iterable of SEL entries.  If clearing is requested,
    the fetch and clear will be done as an atomic operation, assuring
    no entries are dropped.

    :param ipmicmd: The Command object to use to interrogate
    :param clear: Whether to clear the entries upon retrieval.
    """
        records = []
        # First we do a fetch all without reservation, reducing the risk
        # of having a long lived reservation that gets canceled in the middle
        endat = self._fetch_entries(ipmicmd, 0, records)
        if clear and records:  # don't bother clearing if there were no records
            # To do clear, we make a reservation first...
            rsp = ipmicmd.xraw_command(netfn=0xa, command=0x42)
            rsvid = struct.unpack_from('<H', rsp['data'])[0]
            # Then we refetch the tail with reservation (check for change)
            del records[-1]  # remove the record that's about to be duplicated
            self._fetch_entries(ipmicmd, endat, records, rsvid)
            # finally clear the SEL
            # 0XAA means start initiate, 0x524c43 is 'RCL' or 'CLR' backwards
            clrdata = bytearray(struct.pack('<HI', rsvid, 0xAA524C43))
            ipmicmd.xraw_command(netfn=0xa, command=0x47, data=clrdata)
        # Now to fixup the record timestamps... first we need to get the BMC
        # opinion of current time
        _fix_sel_time(records, ipmicmd)
        return records
