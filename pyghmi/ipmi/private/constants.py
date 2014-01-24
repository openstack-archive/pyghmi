# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 IBM Corporation
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

IPMI_BMC_ADDRESS = 0x20
IPMI_SEND_MESSAGE_CMD = 0x34

import pyghmi.constants as const


payload_types = {
    'ipmi': 0x0,
    'sol': 0x1,
    'rmcpplusopenreq': 0x10,
    'rmcpplusopenresponse': 0x11,
    'rakp1': 0x12,
    'rakp2': 0x13,
    'rakp3': 0x14,
    'rakp4': 0x15,
}

#sensor type codes, table 42-3
sensor_type_codes = {
    1: 'Temperature',
    2: 'Voltage',
    3: 'Current',
    4: 'Fan',
    5: 'Chassis Intrusion',
    6: 'Platform Security',
    7: 'Processor',
    8: 'Power Supply',
    9: 'Power Unit',
    0xa: 'Cooling Device',
    0xb: 'Other',
    0xc: 'Memory',
    0xd: 'Drive Bay',
    0xe: 'POST Memory Resize',
    0xf: 'System Firmware Progress',
    0x10: 'Event Log Disabled',
    0x11: 'Watchdog',
    0x12: 'System Event',
    0x13: 'Critical interrupt',
    0x14: 'Button/switch',
    0x15: 'Module/Board',
    0x16: 'Microcontroller/Coprocessor',
    0x17: 'Add-in Card',
    0x18: 'Chassis',
    0x19: 'Chip Set',
    0x1a: 'Other FRU',
    0x1b: 'Cable/Interconnect',
    0x1c: 'Terminator',
    0x1d: 'System Boot',
    0x1e: 'Boot Error',
    0x1f: 'OS Boot',
    0x20: 'OS Stop',
    0x21: 'Slot/Connector',
    0x22: 'System ACPI Power State',
    0x23: 'Watchdog',
    0x24: 'Platform alert',
    0x25: 'Entity Presence',
    0x26: 'Monitor ASIC/IC',
    0x27: 'LAN',
    0x28: 'Management Subsystem Health',
    0x29: 'Battery',
    0x2a: 'Session Audit',
    0x2b: 'Version Change',
    0x2c: 'FRU State',
}

# This is from table 42-2
#For severity, we really have very little to go on in this case
#Optimistically assume 'warning' when generic sensors have something
#to assert

discrete_type_offsets = {
    2: {
        0: {
            'desc': 'Idle',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Active',
            'severity': const.Health.Ok,
        },
        2: {
            'desc': 'Busy',
            'severity': const.Health.Ok,
        },
    },
    3: {
        0: {
            'desc': 'Deasserted',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Asserted',
            'severity': const.Health.Warning,
        },
    },
    4: {
        0: {
            'desc': 'Predictive Failure deasserted',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Predictive Failure',
            'severity': const.Health.Warning,
        },
    },
    5: {
        0: {
            'desc': 'Limit Not Exceeded',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Limit Exceeded',
            'severity': const.Health.Warning,
        },
    },
    6: {
        0: {
            'desc': 'Performance Met',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Perfermance Lags',
            'severity': const.Health.Warning,
        },
    },
    7: {
        0: {
            'desc': 'Ok',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Non-Critical',
            'severity': const.Health.Warning,
        },
        2: {
            'desc': 'Critical',
            'severity': const.Health.Critical,
        },
        3: {
            'desc': 'Non-recoverable',
            'severity': const.Health.Failed,
        },
        4: {
            'desc': 'Non-Critical',
            'severity': const.Health.Warning,
        },
        5: {
            'desc': 'Critical',
            'severity': const.Health.Critical,
        },
        6: {
            'desc': 'Non-recoverable',
            'severity': const.Health.Failed,
        },
        7: {
            'desc': 'Monitor',
            'severity': const.Health.Ok,
        },
        8: {
            'desc': 'Informational',
            'severity': const.Health.Ok,
        },
    },
    8: {
        0: {
            'desc': 'Absent',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Present',
            'severity': const.Health.Ok,
        },
    },
    9: {
        0: {
            'desc': 'Disabled',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Enabled',
            'severity': const.Health.Ok,
        },
    }
}

sensor_type_offsets = {
    # For the security sensors, we assume if armed,
    # the operator considers these to  be critical situations
    5: {
        0: {
            'desc': 'General Chassis Intrusion',
            'severity': const.Health.Critical,
        },
        1: {
            'desc': 'Drive Bay intrusion',
            'severity': const.Health.Critical,
        },
        2: {
            'desc': 'I/O Card area intrusion',
            'severity': const.Health.Critical,
        },
        3: {
            'desc': 'Processor area intrusion',
            'severity': const.Health.Critical,
        },
        4: {
            'desc': 'Lost LAN connection',
            'severity': const.Health.Critical,
        },
        5: {
            'desc': 'Unauthorized dock',
            'severity': const.Health.Critical,
        },
        6: {
            'desc': 'Fan area intrusion',
            'severity': const.Health.Critical,
        },
    },
    6: {
        0: {
            'desc': 'Front Panel Lockout Violation attempt',
            'severity': const.Health.Critical,
        },
        1: {
            'desc': 'Pre-boot password violation - user',
            'severity': const.Health.Critical,
        },
        2: {
            'desc': 'Pre-boot password violation - setup',
            'severity': const.Health.Critical,
        },
        3: {
            'desc': 'Pre-boot password violation - netboot',
            'severity': const.Health.Critical,
        },
        4: {
            'desc': 'Pre-boot password violation',
            'severity': const.Health.Critical,
        },
        5: {
            'desc': 'Out-of-band access password violation',
            'severity': const.Health.Critical,
        },
    },
    7: {
        0: {
            'desc': 'processor IERR',
            'severity': const.Health.Failed,
        },
        1: {
            'desc': 'processor thermal trip',
            'severity': const.Health.Failed,
        },
        2: {
            'desc': 'processor FRB1/BIST failure',
            'severity': const.Health.Failed,
        },
        3: {
            'desc': 'processor FRB2/Hang in POST failure',
            'severity': const.Health.Failed,
        },
        4: {
            'desc': 'processor FRB3/processor startup failure',
            'severity': const.Health.Failed,
        },
        5: {
            'desc': 'processor configuration error',
            'severity': const.Health.Failed,
        },
        6: {
            'desc': 'uncorrectable cpu complex error',
            'severity': const.Health.Failed,
        },
        7: {
            'desc': 'Present',
            'severity': const.Health.Ok,
        },
        8: {
            'desc': 'Disabled',
            'severity': const.Health.Warning,
        },
        9: {
            'desc': 'processor terminator presence detected',
            'severity': const.Health.Ok,
        },
        0xa: {
            'desc': 'processor throttled',
            'severity': const.Health.Warning,
        },
        0xb: {
            'desc': 'uncorrectable machine check exception',
            'severity': const.Health.Failed,
        },
        0xc: {
            'desc': 'correctable machine check exception',
            'severity': const.Health.Warning,
        },
    },
    8: {  # power supply
        0: {
            'desc': 'Present',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'power supply failure',
            'severity': const.Health.Critical,
        },
        2: {
            'desc': 'power supply predictive failure',
            'severity': const.Health.Critical,
        },
        3: {
            'desc': 'power supply input lost',
            'severity': const.Health.Critical,
        },
        4: {
            'desc': 'power supply input out of range or lost',
            'severity': const.Health.Critical,
        },
        5: {
            'desc': 'power supply input out of range',
            'severity': const.Health.Critical,
        },
        6: {
            # clarified by SEL/PET event data 3
            'desc': 'power supply configuration error',
            'severity': const.Health.Warning,
        },
    },
    9: {  # power unit
        0: {
            'desc': 'power off/down',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'power cycle',
            'severity': const.Health.Ok,
        },
        2: {
            'desc': '240VA power down',
            'severity': const.Health.Warning,
        },
        3: {
            'desc': 'interlock power down',
            'severity': const.Health.Ok,
        },
        4: {
            'desc': 'power input lost',
            'severity': const.Health.Warning,
        },
        5: {
            'desc': 'soft power control failure',
            'severity': const.Health.Failed,
        },
        6: {
            'desc': 'power unit failure',
            'severity': const.Health.Critical,
        },
        7: {
            'desc': 'power unit predictive failure',
            'severity': const.Health.Warning,
        },
    },
    0xc: {  # memory
        0: {
            'desc': 'correctable memory error',
            'severity': const.Health.Warning,
        },
        1: {
            'desc': 'uncorrectable memory error',
            'severity': const.Health.Failed,
        },
        2: {
            'desc': 'memory parity',
            'severity': const.Health.Warning,
        },
        3: {
            'desc': 'memory scrub failed',
            'severity': const.Health.Critical,
        },
        4: {
            'desc': 'memory device disabled',
            'severity': const.Health.Warning,
        },
        5: {
            'desc': 'correctable memory error logging limit reached',
            'severity': const.Health.Critical,
        },
        6: {
            'desc': 'Present',
            'severity': const.Health.Ok,
        },
        7: {
            'desc': 'memory configuration error',
            'severity': const.Health.Critical,
        },
        8: {
            'desc': 'spare memory',  # event data 3 available
            'severity': const.Health.Ok,
        },
        9: {
            'desc': 'memory throttled',
            'severity': const.Health.Warning,
        },
        0xa: {
            'desc': 'critical memory overtemperature',
            'severity': const.Health.Critical,
        },
    },
    0xd: {  # drive bay
        0: {
            'desc': 'Present',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'drive fault',
            'severity': const.Health.Critical,
        },
        2: {
            'desc': 'predictive drive failure',
            'severity': const.Health.Warning,
        },
        3: {
            'desc': 'hot spare drive',
            'severity': const.Health.Ok,
        },
        4: {
            'desc': 'drive consitency check in progress',
            'severity': const.Health.Ok,
        },
        5: {
            'desc': 'drive in critical array',
            'severity': const.Health.Critical,
        },
        6: {
            'desc': 'drive in failed array',
            'severity': const.Health.Failed,
        },
        7: {
            'desc': 'rebuild in progress',
            'severity': const.Health.Ok,
        },
        8: {
            'desc': 'rebuild aborted',
            'severity': const.Health.Critical,
        },
    },
    0x1b: {  # Cable/Interconnect
        0: {
            'desc': 'Connected',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Connection error',
            'severity': const.Health.Critical,
        },
    },
    0x25: {  # entity presence
        0: {
            'desc': 'Present',
            'severity': const.Health.Ok,
        },
        1: {
            'desc': 'Absent',
            'severity': const.Health.Ok,
        },
        2: {
            'desc': 'Disabled',
            'severity': const.Health.Ok,
        },
    },
}


#entity ids from table 43-13 entity id codes
entity_ids = {
    0x0: 'unspecified',
    0x1: 'other',
    0x2: 'unknown',
    0x3: 'processor',
    0x4: 'disk or disk bay',
    0x5: 'peripheral bay',
    0x6: 'system management module',
    0x7: 'system board',
    0x8: 'memory module',
    0x9: 'processor module',
    0xa: 'power supply',
    0xb: 'add-in card',
    0xc: 'front panel board',
    0xd: 'back panel board',
    0xe: 'power system board',
    0xf: 'drive backplane',
    0x10: 'system internal expansion board',
    0x11: 'other system board',
    0x12: 'processor board',
    0x13: 'power unit / power domain',
    0x14: 'power module / DC-to-DC converter',
    0x15: 'power management /power distribution board',
    0x16: 'chassis back panel board',
    0x17: 'system chassis',
    0x18: 'sub-chassis',
    0x19: 'other chassis board',
    0x1a: 'disk drive bay',
    0x1b: 'peripheral bay',
    0x1c: 'device bay',
    0x1d: 'fan/cooling device',
    0x1e: 'cooling unit / cooling domain',
    0x1f: 'cable / interconnect',
    0x20: 'memory device',
    0x21: 'system management software',
    0x22: 'system firmware',
    0x23: 'operating system',
    0x24: 'system bus',
    0x25: 'group',
    0x26: 'remote management communication device',
    0x27: 'external environment',
    0x28: 'battery',
    0x29: 'processing blade',
    0x2a: 'connectivity switch',
    0x2b: 'processor/memory module',
    0x2c: 'I/O module',
    0x2d: 'Processor I/O module',
    0x2e: 'management controller firmware',
    0x2f: 'IPMI channel',
    0x30: 'PCI Bus',
    0x31: 'PCIe Bus',
    0x32: 'SCSI Bus',
    0x33: 'SATA/SAS Bus',
    0x34: 'processor / front-side bus',
    0x35: 'real time clock',
    0x37: 'air inlet',
    0x40: 'air inlet',
    0x41: 'processor',
    0x42: 'system board',
}


rmcp_codes = {
    1: ("Insufficient resources to create new session (wait for existing "
        "sessions to timeout)"),
    2: "Invalid Session ID",
    3: "Invalid payload type",
    4: "Invalid authentication algorithm",
    5: "Invalid integrity algorithm",
    6: "No matching integrity payload",
    7: "No matching integrity payload",
    8: "Inactive Session ID",
    9: "Invalid role",
    0xa: "Unauthorized role or privilege level requested",
    0xb: "Insufficient resources to create a session at the requested role",
    0xc: "Invalid username length",
    0xd: "Unauthorized name",
    0xe: "Unauthorized GUID",
    0xf: "Invalid integrity check value",
    0x10: "Invalid confidentiality algorithm",
    0x11: "No Cipher suite match with proposed security algorithms",
    0x12: "Illegal or unrecognized parameter",
}

netfn_codes = {
    "chassis": 0x0,
    "bridge": 0x2,
    "sensorevent": 0x4,
    "application": 0x6,
    "firmware": 0x8,
    "storage": 0xa,
    "transport": 0xc,
}

command_completion_codes = {
    (7, 0x39): {
        0x81: "Invalid user name",
        0x82: "Null user disabled",
    },
    (7, 0x3a): {
        0x81: "No available login slots",
        0x82: "No available login slots for requested user",
        0x83: "No slot available with requested privilege level",
        0x84: "Session sequence number out of range",
        0x85: "Invalid session ID",
        0x86: ("Requested privilege level exceeds requested user permissions "
               "on this channel"),
    },
    (7, 0x3b): {  # Set session privilege level
        0x80: "User is not allowed requested privilege level",
        0x81: "Requested privilege level is not allowed over this channel",
        0x82: "Cannot disable user level authentication",
    },
    (1, 8): {  # set system boot options
        0x80: "Parameter not supported",
        0x81: "Attempt to set set 'set in progress' when not 'set complete'",
        0x82: "Attempt to write read-only parameter",
    },
    (7, 0x48): {  # activate payload
        0x80: "Payload already active on another session",
        0x81: "Payload is disabled",
        0x82: "Payload activation limit reached",
        0x83: "Cannot activate payload with encryption",
        0x84: "Cannot activate payload without encryption",
    },
}

ipmi_completion_codes = {
    0x00: "Success",
    0xc0: "Node Busy",
    0xc1: "Invalid command",
    0xc2: "Invalid command for given LUN",
    0xc3: "Timeout while processing command",
    0xc4: "Out of storage space on BMC",
    0xc5: "Reservation canceled or invalid reservation ID",
    0xc6: "Request data truncated",
    0xc7: "Request data length invalid",
    0xc8: "Request data field length limit exceeded",
    0xc9: "Parameter out of range",
    0xca: "Cannot return number of requested data bytes",
    0xcb: "Requested sensor, data, or record not present",
    0xcc: "Invalid data field in request",
    0xcd: "Command illegal for specified sensor or record type",
    0xce: "Command response could not be provided",
    0xcf: "Cannot execute duplicated request",
    0xd0: "SDR repository in update mode",
    0xd1: "Device in firmware update mode",
    0xd2: "BMC initialization in progress",
    0xd3: "Internal destination unavailable",
    0xd4: "Insufficient privilege level or firmware firewall",
    0xd5: "Command not supported in present state",
    0xd6: "Cannot execute command because subfunction disabled or unavailable",
    0xff: "Unspecified",
}
