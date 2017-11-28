# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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


class Disk(object):
    def __init__(self, name, description=None, id=None, status=None,
                 serial=None, fru=None, stripesize=None):
        """

        :param name: A name descripbing the disk in human readable terms
        :param description: A description of the device
        :param id: Identifier used by the controller
        :param status: Controller indicated status of disk
        :param serial: Serial number of the drive
        :param fru: FRU number of the driver
        """
        self.name = str(name)
        self.description = description
        self.id = id
        self.status = status
        self.serial = serial
        self.fru = fru
        self.stripesize = stripesize


class Array(object):
    def __init__(self, disks=None, raid=None, status=None, volumes=(), id=None,
                 spans=None, hotspares=(), capacity=None,
                 available_capacity=None):
        """

        :param disks: An array of Disk objects
        :param layout: The layout of the Array, generally the RAID level
        :param status: Status of the array according to the controller
        :param id: Unique identifier used by controller to identify
        :param spans: Number of spans for a multi-dimensional array
        :param hotspares: List of Disk objects that are dedicated hot spares
            for this array.
        """
        self.disks = disks
        self.raid = raid
        self.status = status
        self.id = id
        self.volumes = volumes
        self.spans = spans
        self.hotspares = hotspares
        self.capacity = capacity
        self.available_capacity = available_capacity


class Volume(object):
    def __init__(self, name=None, size=None, status=None, id=None,
                 stripesize=None):
        """

        :param name: Name of the volume
        :param size: Size of the volume in MB
        :param status: Controller indicated status of the volume
        :param id: Controller idintefier of a given volume
        :param stripesize: The stripesize of the volume
        """
        self.name = name
        if isinstance(size, int):
            self.size = size
        else:
            strsize = str(size).lower()
            if strsize.endswith('mb'):
                self.size = int(strsize.replace('mb', ''))
            elif strsize.endswith('gb'):
                self.size = int(strsize.replace('gb', '')) * 1000
            elif strsize.endswith('tb'):
                self.size = int(strsize.replace('tb', '')) * 1000 * 1000
            else:
                self.size = size
        self.status = status
        self.id = id
        self.stripesize = stripesize


class ConfigSpec(object):
    def __init__(self, disks=(), arrays=()):
        """A configuration specification of storage

        When returned from a remote system, it describes the current config.
        When given to a remote system, it should only describe the delta
        between current config.

        :param disks:  A list of Disk in the configuration not in an array
        :param arrays: A list of Array objects
        :return:
        """
        self.disks = disks
        self.arrays = arrays
