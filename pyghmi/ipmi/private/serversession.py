# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Lenovo
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
# This represents the server side of a session object
# Split into a separate file to avoid overly manipulating the as-yet
# client-centered session object
import hashlib
import hmac
import os
import pyghmi.ipmi.private.constants as constants
import pyghmi.ipmi.private.session as session
import struct
import uuid


class ServerSession(session.Session):
    def __new__(cls, authdata, kg, clientaddr, netsocket, request, uuid):
        # Need to do default new type behavior.  The normal session
        # takes measures to assure the caller shares even when they
        # didn't try.  We don't have that operational mode to contend
        # with in the server case (one file descriptor per bmc)
        return object.__new__(cls)

    def __init__(self, authdata, kg, clientaddr, netsocket, request, uuid):
        # begin conversation per RMCP+ open session request
        self.uuid = uuid
        self.authdata = authdata
        self.ipmiversion = 2.0
        self.sequencenumber = 0
        self.sessionid = 0
        self.lastpayload = None
        self.broken = False
        self.authtype = 6
        self.integrityalgo = 0
        self.confalgo = 0
        self.kg = kg
        self.socket = netsocket
        self.sockaddr = clientaddr
        session.Session.bmc_handlers[clientaddr] = self
        clienttag = ord(request[0])
        # role = request[1]
        self.clientsessionid = list(struct.unpack('4B', request[4:8]))
        #TODO(jbjohnso): intelligently handle integrity/auth/conf
        #for now, forcibly do cipher suite 3
        self.managedsessionid = list(struct.unpack('4B', os.urandom(4)))
        #table 13-17, 1 for now (hmac-sha1), 3 should also be supported
        #table 13-18, integrity, 1 for now is hmac-sha1-96, 4 is sha256
        #confidentiality: 1 is aes-cbc-128, the only one
        self.privlevel = 4
        response = ([clienttag, 0, self.privlevel, 0] +
                    self.clientsessionid + self.managedsessionid +
                    [
                      0, 0, 0, 8, 1, 0, 0, 0,  # auth
                      1, 0, 0, 8, 1, 0, 0, 0, # integrity
                      2, 0, 0, 8, 1, 0, 0, 0,  # privacy
                    ])
        self.send_payload(response,
                          constants.payload_types['rmcpplusopenresponse'],
                          retry=False)

    def _got_rmcp_openrequest(self, data):
        raise('TODO: handle open session retry after dropped rakp2')

    def _got_rakp1(self, data):
        print 'got rakp1: ' + repr(data)
        clienttag = data[0]
        remoterandomunumber = data[8:24]
        rolem = data[24]
        namepresent = data[27]
        if namepresent == 0:
            #ignore null username for now
            return
        usernamebytes = data[28:]
        username = struct.pack('%dB' % len(usernamebytes), *usernamebytes)
        if username not in self.authdata:
            # don't think about invalid usernames for now
            return
        uuidbytes = self.uuid.bytes
        uuidbytes = list(struct.unpack('%dB' % len(uuidbytes), uuidbytes))
        myrandombytes = list(struct.unpack('16B', os.urandom(16)))
        hmacdata = (self.clientsessionid + self.managedsessionid +
                    remoterandomunumber + myrandombytes + uuidbytes +
                    [rolem, len(username)])
        hmacdata = struct.pack('%dB' % len(hmacdata), *hmacdata)
        hmacdata += username
        authcode = hmac.new(
            self.authdata[username], hmacdata, hashlib.sha1).digest()
        authcode = list(struct.unpack('%dB' % len(authcode), authcode))
        print repr(authcode)
        newmessage = ([clienttag, 0, 0, 0] + self.clientsessionid +
                      myrandombytes + uuidbytes + authcode)

        print 'want to send rakp2 now...'
        self.send_payload(newmessage, constants.payload_types['rakp2'],
                          retry=False)

    def _got_rakp2(self, data):
        # stub, server should not think about rakp2
        pass

    def _got_rakp3(self, data):
        print 'got rakp3: ' + repr(data)

    def _got_rakp4(self, data):
        # stub, server should not think about rakp4
        pass

    def _timedout(self):
        """Expire a client session after a period of inactivity

        After the session inactivity timeout, this invalidate the client
        session.
        """
        #for now, we will have a non-configurable 60 second timeout
        pass

    def _handle_channel_auth_cap(self, request):
        """Handle incoming channel authentication capabilities request

        This is used when serving as an IPMI target to service client
        requests for client authentication capabilities
        """
        pass


class IpmiServer(object):
    #auth capabilities for now is a static payload
    #for now always completion code 0, otherwise ignore
    #authentication type fixed to ipmi2, ipmi1 forbidden
    # 0b10000000

    def __init__(self, authdata, port=623, bmcuuid=None):
        """Create a new ipmi server instance.

        :param authdata: A dict or object with .get() to provide password
                        lookup by username.  This does not support the full
                        complexity of what IPMI can support, only a
                        reasonable subset.
        :param port: The default port number to bind to.  Defaults to the
                     standard 623
        """
        if bmcuuid is None:
            self.uuid = uuid.uuid4()
        else:
            self.uuid = bmcuuid
        lanchannel = 1
        authtype = 0b10000000  # ipmi2 only
        authstatus = 0b00000100  # change based on authdata/kg
        chancap = 0b00000010  # ipmi2 only
        oemdata = (0, 0, 0, 0)
        self.authdata = authdata
        self.authcap = struct.pack('BBBBBBBBB', 0, lanchannel, authtype,
                                   authstatus, chancap, *oemdata)
        self.kg = None
        self.timeout = 60
        self.serversocket = session.Session._assignsocket(('::', port, 0, 0))
        print "bound it"
        session.Session.bmc_handlers[self.serversocket] = self
        print "set up as handler"

    def send_auth_cap(self, myaddr, mylun, clientaddr, clientlun, sockaddr):
        header = '\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'
        headerdata = (clientaddr, clientlun | (7 << 2))
        headersum = session._checksum(*headerdata)
        header += struct.pack('BBBBBB',
                              *(headerdata + (headersum, myaddr, mylun, 0x38)))
        header += self.authcap
        bodydata = struct.unpack('B' * len(header[17:]), header[17:])
        header += chr(session._checksum(*bodydata))
        session._io_sendto(self.serversocket, header, sockaddr)

    def sessionless_data(self, data, sockaddr):
        """Examines unsolocited packet and decides appropriate action.

        For a listening IpmiServer, a packet without an active session
        comes here for examination.  If it is something that is utterly
        sessionless (e.g. get channel authentication), send the appropriate
        response.  If it is a get session challenge or open rmcp+ request,
        spawn a session to handle the context.
        """
        if len(data) < 22:
            return
        if not (data[0] == '\x06' and data[2:4] == '\xff\x07'):  # not ipmi
            return
        if data[4] == '\x06':  # ipmi 2 payload...
            payloadtype = data[5]
            if payloadtype not in ('\x00', '\x10'):
                return
            if payloadtype == '\x10':  # new session to handle conversation
                ServerSession(self.authdata, self.kg, sockaddr,
                              self.serversocket, data[16:], self.uuid)
                return
            data = data[13:]  # ditch 13 bytes so the payload works out
        myaddr, netfnlun = struct.unpack('2B', data[14:16])
        netfn = (netfnlun & 0b11111100) >> 2
        mylun = netfnlun & 0b11
        if netfn == 6:  # application request
            if data[19] == '\x38':  # cmd = get channel auth capabilities
                verchannel, level = struct.unpack('2B', data[20:22])
                version = verchannel & 0b10000000
                if version != 0b10000000:
                    return
                channel = verchannel & 0b1111
                if channel != 0xe:
                    return
                (clientaddr, clientlun) = struct.unpack('BB', data[17:19])
                level &= 0b1111
                self.send_auth_cap(myaddr, mylun, clientaddr, clientlun,
                                   sockaddr)

    def set_kg(self, kg):
        """Sets the Kg for the BMC to use

        In RAKP, Kg is a BMC-specific integrity key that can be set.  If not
        set, Kuid is used for the integrity key"""
        try:
            self.kg = kg.encode('utf-8')
        except AttributeError:
            self.kg = kg

    def logout(self):
        pass
    