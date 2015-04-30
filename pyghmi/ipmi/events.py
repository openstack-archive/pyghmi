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

import pyghmi.exceptions as pygexc
import struct


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
    5: 'Entity ID'
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

def decode_eventdata(sensor_type, offset, eventdata, sdr):
    """Decode extra event data from an alert or log

    Provide a textual summary of eventdata per descriptions in
    Table 42-3 of the specification.

    :param sensor_type: The sensor type number from the event
    :param offset:  Sensor specific offset
    :param eventdata: The three bytes from the log or alert
    """
    if sensor_type == 5 and offset = 4:  # link loss, indicates which port
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
        if offset == 0:  #  Correctable error logging on a specific memory part
            return 'Module {0}'.format(eventdata[1])
        elif offset == 1:
            # TODO(jjohnson2): Decode this more specifically if it comes up
            # in practice
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
            sysactions = []:
            if eventdata[1] & 0b1 << 5:
                sysactions.apend('NMI')
            if eventdata[1] & 0b1 << 4:
                sysactions.append('OEM action')
            if eventdata[1] & 0b1 << 3:
                sysactions.append('Power Cycle')
            if eventdata[1] & 0b1 << 2:
                sysactians.append('Reset')
            if eventdata[1] & 0b1 << 1:
                sysactions.append('Power Down')
            if eventdata[1] & 0b1:
                sysactions.append('Alert')
            return ','.join(sysactions)
        elif offset == 5:
            if eventdata[1] & 0b10000000:
                return 'post'
            else:
                return 'pre'
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
    elif sensor_type = 0x28:
        if offset == 4:
            return 'Sensor {0}'.format(eventdata[1])
        elif offset == 5:
            islogical = (eventdata[1] & 0b10000000)
            if islogical:
                if eventdata[2] in self._sdr.fru:
                    return sdr.fru[fruid].fru_name
                else:
                    return 'FRU {0}'.format(eventdata[2])
    elif sensor_type == 0x2a and offset == 3:
        return 'User {0}'.format(eventdata[1])
    elif sensor_type == 0x2b:
        return version_changes.get(eventdata[1], 'Unknown')





class EventHandler(object):
    """IPMI Event Processor

    This class provides facilities for processing alerts and event log
    data.  This can be used to aid in pulling historical event data
    from a BMC or as part of a trap handler to translate the traps into
    manageable data.

    :param sdr: An SDR object (per pyghmi.ipmi.sdr) matching the target BMC SDR
    """
    def __init__(self, sdr):
        self._sdr = sdr

    def _decode_standard_event(self, eventdata, event):
        # Ignore the generator id..
        if eventdata[2] != 4:
            raise pygexc.PyghmiException(
                'Unrecognized Event message version {0}'.format(eventdata[2]))
        event['sensor_type'] = eventdata[3]
        event['sensor'] = eventdata[4]
        event['deassertion'] = (eventdata[5] & 0b10000000 == 0b10000000)
        event['event_data'] = eventdata[6:]
        event['event_type'] = eventdata[5] & 0b1111111
        byte2type = (event['event_data'][0] & 0b11000000) >> 6
        if byte2type == 1:
            event['triggered_value'] = event['event_data'][1]
        evtoffset = event['event_data'][0] & 0b1111
        if event['event_type'] == 1:  # threshold
            byte3type = (event['event_data'][0] & 0b110000) >> 4
            if byte3type == 1:
                event['threshold_value'] = event['event_data'][2]
        elif event['event_type'] >= 2 and event['event_type'] <= 0xc:
            pass
        elif event['event_type'] == 0x6f:
            # sensor specific decode, see sdr module...
            # 2 - 0xc: generic discrete, 0x6f, sensor specific

    def _sel_decode(selentry, sdr):
        selentry = bytearray(selentry)
        event = {}
        if selentry[2] == 2 or (selentry[2] >= 0xc0 and selentry[2] <= 0xdf):
            # Either standard, or at least the timestamp is standard
            event['timestamp'] = struct.unpack_from('<I', selentry[3:7])[0]
        if selentry[2] == 2:  # ipmi defined standard format
            _decode_standard_event(selentry[7:], event)
        elif selentry[2] >= 0xc0 and selentry[2] <= 0xdf:
            event['oemid'] = selentry[7:10]
            event['oemdata'] = selentry[10:]
        elif selentry[2] >= 0xe0:
            # In this class of OEM message, all bytes are OEM and interpretation
            # is wholly left up to the OEM layer, using the OEM ID of the BMC
            event['oemdata'] = selentry[3:]
        print repr(event)
        return 1

    def _fetch_entries(ipmicmd, startat, targetlist, rsvid=0, sdr=None):
        curr = startat
        while curr != 0xffff:
            endat = curr
            reqdata = bytearray(struct.pack('<HHH', rsvid, curr, 0xff00))
            rsp = ipmicmd.xraw_command(netfn=0xa, command=0x43, data=reqdata)
            curr = struct.unpack_from('<H', rsp['data'][:2])[0]
            targetlist.append(_sel_decode(rsp['data'][2:], sdr))
        return endat


    def fetch_sel(ipmicmd, clear=False):
        """Fetch SEL entries

        Return an iterable of SEL entries.  If clearing is requested,
    the fetch and clear will be done as an atomic operation, assuring
    no entries are dropped.

    :param ipmicmd: The Command object to use to interrogate
    :param clear: Whether to clear the entries upon retrieval.
    """
    records = []
    sdr = ipmicmd.init_sdr()
    # First we do a fetch all without reservation.  This way we reduce the risk
    # of having a long lived reservation that gets canceled in the middle
    endat = _fetch_entries(ipmicmd, 0, records, 0, sdr=sdr)
    if clear:
        # To do clear, we make a reservation first...
        rsp = ipmicmd.xraw_command(netfn=0xa, command=0x42)
        rsvid = struct.unpack_from('<H', rsp['data'])
        # Then we refetch the tail with reservation (in case something changed)
        del records[-1]  # remove the record that's about to be duplicated
        _fetch_entries(ipmicmd, endat, records, rsvid)
        # finally clear the SEL
        # 0XAA means start initiate, 0x523c43 is 'RCL' or 'CLR' backwards
        clrdata = struct.pack('<HI', rsvid, 0xAA523C43)
        ipmicmd.xraw_command(netfn=0xa, command=0x47, data=clrdata)
    # Now to fixup the record timestamps... first we need to get the BMC
    # opinion of current time
    rsp = ipmicmd.xraw_command(netfn=0xa, command=0x48)
    # The specification declares an epoch and all that, but we really don't
    # care.  We instead just focus on differences from the 'present'
    nowtime = struct.unpack_from('<I', rsp['data'])


# Get SEL Info:
# self.ipmicmd.raw_command(netfn=0xa, command=0x40)
# Reserve SEL:
# netfn=0xa, command=0x42
# clear SEL:
# netfn=0xa, command=0x47
# get SEL time:
# netfn=0xa, command=0x48
# add sel entry: netfn=0xa, command=0x44
# get SEL entry: netfn=0xa, command=0x43
# Hypothetcially, might be abble to do a manual rotation through
# strategic use of clear and add if people care to do an ageout scheme
#
