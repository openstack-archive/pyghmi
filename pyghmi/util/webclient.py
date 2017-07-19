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

import json
import pyghmi.exceptions as pygexc
import socket
import ssl

try:
    import Cookie
    import httplib
except ImportError:
    import http.client as httplib
    import http.cookies as Cookie

__author__ = 'jjohnson2'


# Used as the separator for form data
BND = 'TbqbLUSn0QFjx9gxiQLtgBK4Zu6ehLqtLs4JOBS50EgxXJ2yoRMhTrmRXxO1lkoAQdZx16'

# We will frequently be dealing with the same data across many instances,
# consolidate forms to single memory location to get benefits..
uploadforms = {}


def get_upload_form(filename, data):
    try:
        return uploadforms[filename]
    except KeyError:
        form = '--' + BND + '\r\nContent-Disposition: form-data; ' \
                            'name="{0}"; filename="{0}"\r\n'.format(filename)
        form += 'Content-Type: application/octet-stream\r\n\r\n' + data
        form += '\r\n--' + BND + '--\r\n'
        uploadforms[filename] = form
        return form


class SecureHTTPConnection(httplib.HTTPConnection, object):
    default_port = httplib.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_certs=None, strict=None, verifycallback=None, clone=None,
                 **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 60
        self.thehost = host
        self.theport = port
        httplib.HTTPConnection.__init__(self, host, port, strict, **kwargs)
        self.cert_reqs = ssl.CERT_NONE  # verification will be done ssh style..
        if clone:
            self._certverify = clone._certverify
            self.cookies = clone.cookies.copy()
            self.stdheaders = clone.stdheaders.copy()
        else:
            self._certverify = verifycallback
            self.cookies = {}
            self.stdheaders = {}

    def dupe(self):
        return SecureHTTPConnection(self.thehost, self.theport, clone=self)

    def set_header(self, key, value):
        self.stdheaders[key] = value

    def connect(self):
        plainsock = socket.create_connection((self.host, self.port), 60)
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

    def grab_json_response(self, url, data=None):
        if data:
            self.request('POST', url, data)
        else:
            self.request('GET', url)
        rsp = self.getresponse()
        if rsp.status == 200:
            return json.loads(rsp.read())
        rsp.read()
        return {}

    def upload(self, url, filename, data=None):
        """Upload a file to the url

        :param url:
        :param filename: The name of the file
        :param data: A file object or data to use rather than reading from
                     the file.
        :return:
        """
        if data is None:
            data = open(filename, 'rb')
        if isinstance(data, file):
            data = data.read()
        form = get_upload_form(filename, data)
        ulheaders = self.stdheaders.copy()
        ulheaders['Content-Type'] = 'multipart/form-data; boundary=' + BND
        self.request('POST', url, form, ulheaders)
        rsp = self.getresponse()
        # peer updates in progress should already have pointers,
        # subsequent transactions will cause memory to needlessly double,
        # but easiest way to keep memory relatively low
        del uploadforms[filename]
        if rsp.status != 200:
            raise Exception('Unexpected response in file upload: ' +
                            rsp.read())
        return rsp.read()

    def request(self, method, url, body=None, headers=None):
        if headers is None:
            headers = self.stdheaders.copy()
        if method == 'GET' and 'Content-Type' in headers:
            del headers['Content-Type']
        if self.cookies:
            cookies = []
            for ckey in self.cookies:
                cookies.append('{0}={1}'.format(ckey, self.cookies[ckey]))
            headers['Cookie'] = '; '.join(cookies)
        return super(SecureHTTPConnection, self).request(method, url, body,
                                                         headers)
