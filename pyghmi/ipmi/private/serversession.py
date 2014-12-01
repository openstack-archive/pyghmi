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

class IpmiServer(session.Session):
    def __new__(cls, authdata, port=623, kg=None):
        # Need to do default new type behavior.  The normal session
        # takes measures to assure the caller shares even when they
        # didn't try.  We don't have that operational mode to contend
        # with in the server case (one file descriptor per bmc)
        return object.__new__(cls)

    def set_kg(self, kg):
        """Sets the Kg for the BMC to use

        In RAKP, Kg is a BMC-specific integrity key that can be set.  If not set,
        Kuid is used for the integrity key"""
        try:
            self.kg = kg.encode('utf-8')
        except AttributeError:
            self.kg = kg

    def __init__(self, authdata, port=623):
        """Create a new ipmi server instance.

        :param authdata: A dict or object with .get() to provide password lookup
                         by username.  This does not support the full complexity
                         of what IPMI can support, only a sane subset.
        :param port: The default port number to bind to.  Defaults to the standard
                     623
        """
        self.kg = None
        self.serversocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.serversocket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.serversocket.bind(('::', port, 0, 0))


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