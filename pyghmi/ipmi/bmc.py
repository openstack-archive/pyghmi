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

__author__ = 'jjohnson2@lenovo.com'

import pyghmi.ipmi.command as ipmicommand
import pyghmi.ipmi.private.session as ipmisession
import pyghmi.ipmi.private.serversession as serversession


class Bmc(serversession.IpmiServer):
    def cold_reset(self):
        raise NotImplementedError

    def power_off(self):
        raise NotImplementedError

    def power_on(self):
        raise NotImplementedError

    def power_cycle(self):
        raise NotImplementedError

    def power_reset(self):
        raise NotImplementedError

    def power_shutdown(self):
        raise NotImplementedError

    def get_power_state(self):
        raise NotImplementedError

    @staticmethod
    def handle_missing_command(session):
        session.send_ipmi_response(code=0xc1)

    def get_chassis_status(self, session):
        try:
            powerstate = self.get_power_state()
        except NotImplementedError:
            return session.send_ipmi_response(code=0xc1)
        if powerstate in ipmicommand.power_states:
            powerstate = ipmicommand.power_states[powerstate]
        if powerstate not in (0, 1):
            raise Exception('BMC implementation mistake')
        statusdata = [powerstate, 0, 0]
        session.send_ipmi_response(data=statusdata)

    def control_chassis(self, request, session):
        rc = 0
        try:
            directive = request['data'][0]
            if directive == 0:
                rc = self.power_off()
            elif directive == 1:
                rc = self.power_on()
            elif directive == 2:
                rc = self.power_cycle()
            elif directive == 3:
                rc = self.power_reset()
            elif directive == 5:
                rc = self.power_shutdown()
            session.send_ipmi_response(code=rc)
        except NotImplementedError:
            session.send_ipmi_response(code=0xcc)

    def handle_raw_request(self, request, session):
        try:
            if request['netfn'] == 6:
                if request['command'] == 1:  # get device id
                    return self.send_device_id(session)
                elif request['command'] == 2:  # cold reset
                    return session.send_ipmi_response(code=self.cold_reset())
            elif request['netfn'] == 0:
                if request['command'] == 1:  # get chassis status
                    return self.get_chassis_status(session)
                elif request['command'] == 2:  # chassis control
                    return self.control_chassis(request, session)
            session.send_ipmi_response(code=0xc1)
        except NotImplementedError:
            session.send_ipmi_response(code=0xc1)

    @classmethod
    def listen(cls):
        while True:
            ipmisession.Session.wait_for_rsp(30)

