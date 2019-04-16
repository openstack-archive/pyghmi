# Copyright 2019 Lenovo Corporation
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

import os
import pyghmi.exceptions as exc


class OEMHandler(object):
    def __init__(self, sysinfo, sysurl, webclient, cache):
        self._varsysinfo = sysinfo
        self._varsysurl = sysurl
        self._urlcache = cache
        self.webclient = webclient

    def _get_cache(self, url):
        now = os.times()[4]
        cachent = self._urlcache.get(url, None)
        if cachent and cachent['vintage'] > now - 30:
            return cachent['contents']
        return None

    def get_description(self):
        return {}

    def _do_web_request(self, url, payload=None, method=None, cache=True):
        res = None
        if cache and payload is None and method is None:
            res = self._get_cache(url)
        if res:
            return res
        wc = self.webclient.dupe()
        res = wc.grab_json_response_with_status(url, payload, method=method)
        if res[1] < 200 or res[1] >= 300:
            raise exc.PyghmiException(res[0])
        if payload is None and method is None:
            self._urlcache[url] = {
                'contents': res[0],
                'vintage': os.times()[4]
            }
        return res[0]
