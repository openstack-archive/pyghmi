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
import pyghmi.ipmi.private.session as session
import socket

class ServerSession(session.Session):
    def __new__(cls, authdata, kg=None):
        # Need to do default new type behavior.  The normal session
        # takes measures to assure the caller shares even when they
        # didn't try.  We don't have that operational mode to contend
        # with in the server case (one file descriptor per bmc)
        return object.__new__(cls)

    def __init__(self, authdata, kg=None):
        if kg is not None:
            self.kg = kg

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
class IpmiServer(object):

    def __init__(self, authdata, port=623):
        """Create a new ipmi server instance.

        :param authdata: A dict or object with .get() to provide password lookup
                         by username.  This does not support the full complexity
                         of what IPMI can support, only a sane subset.
        :param port: The default port number to bind to.  Defaults to the standard
                     623
        """
        self.kg = None
        self.timeout = 60
        self.serversocket = session.Session._assignsocket(('::', port, 0, 0))
        print "bound it"
        session.Session.bmc_handlers[self.serversocket] = self
        print "set up as handler"


    def sessionless_data(self, data, sockaddr):
        """Examines unsolocited packet and decides appropriate action.

        For a listening IpmiServer, a packet without an active session
        comes here for examination.  If it is something that is utterly
        sessionless (e.g. get channel authentication), send the appropriate
        response.  If it is a get session challenge or open rmcp+ request,
        spawn a session to handle the context.
        """
        print repr(data)

    def set_kg(self, kg):
        """Sets the Kg for the BMC to use

        In RAKP, Kg is a BMC-specific integrity key that can be set.  If not set,
        Kuid is used for the integrity key"""
        try:
            self.kg = kg.encode('utf-8')
        except AttributeError:
            self.kg = kg

    def logout(self):
        pass