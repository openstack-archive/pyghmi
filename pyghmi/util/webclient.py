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

# This provides ability to do HTTPS in a manner like ssh host keys for the
# sake of typical internal management devices.  Compatibility back to python
# 2.6 as is found in commonly used enterprise linux distributions.

__author__ = 'jjohnson2'

import Cookie
import httplib
import json
import pyghmi.exceptions as pygexc
import socket
import ssl


class SecureHTTPConnection(httplib.HTTPConnection, object):
    default_port = httplib.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_certs=None, strict=None, verifycallback=None, **kwargs):
        httplib.HTTPConnection.__init__(self, host, port, strict, **kwargs)
        self.cert_reqs = ssl.CERT_NONE  # verification will be done ssh style..
        self._certverify = verifycallback
        self.cookies = {}

    def connect(self):
        plainsock = socket.create_connection((self.host, self.port))
        self.sock = ssl.wrap_socket(plainsock, cert_reqs=self.cert_reqs)
        # txtcert = self.sock.getpeercert()  # currently not possible
        bincert = self.sock.getpeercert(binary_form=True)
        if not self._certverify(bincert):
            raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                 bincert)

    def getresponse(self):
        rsp = super(SecureHTTPConnection, self).getresponse()
        for hdr in rsp.msg.headers:
            if hdr.startswith('Set-Cookie:'):
                c = Cookie.BaseCookie(hdr[11:])
                for k in c:
                    self.cookies[k] = c[k].value
        return rsp

    def grab_json_response(self, url):
        self.request('GET', url)
        rsp = self.getresponse()
        if rsp.status == 200:
            return json.loads(rsp.read())

    def request(self, method, url, body=None, headers=None):
        if headers is None:
            headers = {}
        if self.cookies:
            cookies = []
            for ckey in self.cookies:
                cookies.append('{0}={1}'.format(ckey, self.cookies[ckey]))
            headers['Cookie'] = '; '.join(cookies)
        return super(SecureHTTPConnection, self).request(method, url, body,
                                                         headers)
