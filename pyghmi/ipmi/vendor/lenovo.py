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

# This represents the entry point to lenovo specific extensions

class oemcommand(object):

    def __init__(self, ipmicmd):
        """A handler for vendor extensions

        :param ipmicmd: An ipmi command object
        """""
        self.ipmicmd = ipmicmd

    def get_fw_configuration(self):