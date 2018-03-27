# Copyright 2015-2017 Lenovo
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


def get_upload_form(filename, data, formname, otherfields):
    if not formname:
        formname = filename
    try:
        return uploadforms[filename]
    except KeyError:
        try:
            data = data.read()
        except AttributeError:
            pass
        form = '--' + BND + '\r\nContent-Disposition: form-data; ' \
                            'name="{0}"; filename="{1}"\r\n'.format(formname,
                                                                    filename)
        form += 'Content-Type: application/octet-stream\r\n\r\n' + data
        for ofield in otherfields:
            form += '\r\n--' + BND + '\r\nContent-Disposition: form-data; ' \
                'name="{0}"\r\n\r\n{1}'.format(ofield, otherfields[ofield])
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
        self.broken = False
        self.thehost = host
        self.theport = port
        httplib.HTTPConnection.__init__(self, host, port, strict, **kwargs)
        self.cert_reqs = ssl.CERT_NONE  # verification will be done ssh style..
        if clone:
            self._certverify = clone._certverify
            self.cookies = clone.cookies
            self.stdheaders = clone.stdheaders
        else:
            self._certverify = verifycallback
            self.cookies = {}
            self.stdheaders = {}

    def dupe(self):
        return SecureHTTPConnection(self.thehost, self.theport, clone=self)

    def set_header(self, key, value):
        self.stdheaders[key] = value

    def connect(self):
        addrinfo = socket.getaddrinfo(self.host, self.port)[0]
        # workaround problems of too large mtu, moderately frequent occurance
        # in this space
        plainsock = socket.socket(addrinfo[0])
        plainsock.settimeout(60)
        try:
            plainsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1456)
        except socket.error:
            pass
        plainsock.connect(addrinfo[4])
        self.sock = ssl.wrap_socket(plainsock, cert_reqs=self.cert_reqs)
        # txtcert = self.sock.getpeercert()  # currently not possible
        bincert = self.sock.getpeercert(binary_form=True)
        if not self._certverify(bincert):
            raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                 bincert)

    def getresponse(self):
        try:
            rsp = super(SecureHTTPConnection, self).getresponse()
            for hdr in rsp.msg.headers:
                if hdr.startswith('Set-Cookie:'):
                    c = Cookie.BaseCookie(hdr[11:])
                    for k in c:
                        self.cookies[k] = c[k].value
        except httplib.BadStatusLine:
            self.broken = True
            raise
        return rsp

    def grab_json_response(self, url, data=None, referer=None):
        webclient = self.dupe()
        if isinstance(data, dict):
            data = json.dumps(data)
        if data:
            webclient.request('POST', url, data, referer=referer)
        else:
            webclient.request('GET', url, referer=referer)
        rsp = webclient.getresponse()
        if rsp.status == 200:
            return json.loads(rsp.read())
        rsp.read()
        return {}

    def upload(self, url, filename, data=None, formname=None,
               otherfields=()):
        """Upload a file to the url

        :param url:
        :param filename: The name of the file
        :param data: A file object or data to use rather than reading from
                     the file.
        :return:
        """
        if data is None:
            data = open(filename, 'rb')
        form = get_upload_form(filename, data, formname, otherfields)
        ulheaders = self.stdheaders.copy()
        ulheaders['Content-Type'] = 'multipart/form-data; boundary=' + BND
        webclient = self.dupe()
        webclient.request('POST', url, form, ulheaders)
        rsp = webclient.getresponse()
        # peer updates in progress should already have pointers,
        # subsequent transactions will cause memory to needlessly double,
        # but easiest way to keep memory relatively low
        try:
            del uploadforms[filename]
        except KeyError:  # something could have already deleted it
            pass
        if rsp.status != 200:
            raise Exception('Unexpected response in file upload: ' +
                            rsp.read())
        return rsp.read()

    def request(self, method, url, body=None, headers=None, referer=None):
        if headers is None:
            headers = self.stdheaders.copy()
        if method == 'GET' and 'Content-Type' in headers:
            del headers['Content-Type']
        if method == 'POST' and body and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.cookies:
            cookies = []
            for ckey in self.cookies:
                cookies.append('{0}={1}'.format(ckey, self.cookies[ckey]))
            cookies_header = '; '.join(cookies)
            if headers.get('Cookie', None) is None:
                headers['Cookie'] = cookies_header
            else:
                headers['Cookie'] += '; ' + '; '.join(cookies)
        if referer:
            headers['Referer'] = referer
        try:
            return super(SecureHTTPConnection, self).request(method, url, body,
                                                             headers)
        except httplib.CannotSendRequest:
            self.broken = True
            raise
