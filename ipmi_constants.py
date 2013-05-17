

payload_types = {
    'ipmi': 0x0,
    'sol' : 0x1,
    'rmcpplusopenreq': 0x10,
    'rmcpplusopenresponse': 0x11,
    'rakp1': 0x12,
    'rakp2': 0x13,
    'rakp3': 0x14,
    'rakp4': 0x15,
}

rmcp_codes = {
    1: 'Insufficient resources to create new session (wait for existing sessions to timeout)',
    2: 'Invalid Session ID',
    3: 'Invalid payload type',
    4: 'Invalid authentication algorithm',
    5: 'Invalid integrity algorithm',
    6: 'No matching integrity payload',
    7: 'No matching integrity payload',
    8: 'Inactive Session ID',
    9: 'Invalid role',
    0xa: 'Unauthorized role or privilege level requested',
    0xb: 'Insufficient resources tocreate a session at the requested role',
    0xc: 'Invalid username length',
    0xd: 'Unauthorized name',
    0xe: 'Unauthorized GUID',
    0xf: 'Invalid integrity check value',
    0x10: 'Invalid confidentiality algorithm',
    0x11: 'No Cipher suite match with proposed security algorithms',
    0x12: 'Illegal or unrecognized parameter',
}

