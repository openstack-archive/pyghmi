"""
@author: Jarrod Johnson <jbjohnso@us.ibm.com>

Copyright 2013 IBM Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from ipmi.private.session import Session, call_with_optional_args
def _raiseorcall(callback,response,args=None):
    if callback is None:
        if 'error' in response:
            raise Exception(response['error'])
    else:
        call_with_optional_args(callback,args)

boot_devices = {
    'net': 4,
    'network': 4,
    'pxe': 4,
    'hd': 8,
    'cd': 0x14,
    'cdrom': 0x14,
    'dvd': 0x14,
    'floppy': 0x3c,
    'default': 0x0,
    'setup': 0x18,
    'f1': 0x18,
    1: 'network',
    2: 'hd',
    5: 'optical',
    6: 'setup',
    0: 'default'
}

power_states = {
    "off": 0,
    "on": 1,
    "reset": 3,
    "softoff": 5,
    "shutdown": 5,
    "boot": -1, #not a valid direct boot state, but here for convenience of 'in' statement
}
    
class Command(object):
    """Send IPMI commands to BMCs.
    
    This object represents a persistent session to an IPMI device (bmc) and 
    allows the caller to reuse a single session to issue multiple commands.
    This class can be used in a synchronous (wait for answer and return) or 
    asynchronous fashion (return immediately and provide responses by 
    callbacks).  Synchronous mode is the default behavior.

    For asynchronous mode, simply pass in a callback function.  It is 
    recommended to pass in an instance method to callback and ignore the 
    callback_args parameter. However, callback_args can optionally be populated 
    if desired.

    :param bmc: hostname or ip address of the BMC
    :param userid: username to use to connect
    :param password: password to connect to the BMC
    :param kg: Optional parameter to use if BMC has a particular Kg configured
    """

    def __init__(self,bmc,userid,password,kg=None):
        #TODO(jbjohnso): accept tuples and lists of each parameter for mass 
        #operations without pushing the async complexities up the stack
        self.ipmi_session=Session(bmc=bmc,
                                       userid=userid,
                                       password=password,
                                       kg=kg)

    def get_bootdev(self,callback=None,callback_args=None):
        """Get current boot device override information.

        Provides the current requested boot device.  Be aware that not all IPMI
        devices support this.  Even in BMCs that claim to, occasionally the BIOS
        or UEFI fail to honor it. This is usually only applicable to the next 
        reboot.
    
        :param callback: optional callback
        :param callback_args: optional arguments to callback 
        :returns: dict or True -- If callback is not provided, the response
                                  will be provided in the return
        """
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        self.ipmi_session.raw_command(netfn=0,
                                      command=9,
                                      data=(5,0,0),
                                      callback=self._got_bootdev)
        return self._waitifsync()

    def _waitifsync(self):
        self.requestpending=True
        if self.commandcallback is None:
            while self.requestpending:
                Session.wait_for_rsp()
            return self.lastresponse
        return True
        
    def set_power(self,powerstate,wait=False,callback=None,callback_args=None):
        """Request power state change

        :param powerstate:
                            * on -- Request system turn on
                            * off -- Request system turn off without waiting for                              OS to shutdown
                            * shutdown -- Have system request OS proper shutdown
                            * reset -- Request system reset without waiting for
                              OS
                            * boot -- If system is off, then 'on', else 'reset'
        :param wait: If True, do not return or callback until system actually
                     completes requested state change
        :param callback: optional callback
        :param callback_args: optional arguments to callback 
        :returns: dict or True -- If callback is not provided, the response
        """
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        if powerstate not in power_states:
            _raiseorcall(self.commandcallback,
                         {'error': 
                          "Unknown power state %s requested"%powerstate},
                         self.commandcallbackargs)
        self.newpowerstate=powerstate
        self.wait_for_power=wait
        self.ipmi_session.raw_command(netfn=0,
                                      command=1,
                                      callback=self._set_power_with_chassis_info
                                     )
        return self._waitifsync()

    def _set_power_with_chassis_info(self,response):
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        if self.newpowerstate=='boot':
            self.newpowerstate = 'on' if self.powerstate=='off' else 'reset'
        self.ipmi_session.raw_command(netfn=0,
                                      command=2,
                                      data=[power_states[self.newpowerstate]],
                                      callback=self._power_set)

    def _power_set(self,response):
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        self.lastresponse={'pendingpowerstate': self.newpowerstate}
        if (self.wait_for_power and 
           self.newpowerstate in ('on','off','shutdown','softoff')):
            if self.newpowerstate in ('softoff','shutdown'):
                self.waitpowerstate='off'
            else:
                self.waitpowerstate=self.newpowerstate
            self.ipmi_session.raw_command(netfn=0,
                                          command=1,
                                          callback=self._power_wait)
        else:
            self.requestpending=False
            if self.commandcallback:
                call_with_optional_args(self.commandcallback,
                                        self.lastresponse,
                                        self.commandcallbackargs)

    def _power_wait(self,response):
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        if self.powerstate==self.waitpowerstate:
            self.requestpending=False
            self.lastresponse={'powerstate': self.powerstate}
            if self.commandcallback:
                call_with_optional_args(self.commandcallback,
                                        self.lastresponse,
                                        self.commandcallbackargs)
            return
        self.ipmi_session.raw_command(netfn=0,
                                      command=1,
                                      callback=self._power_wait)

    def set_bootdev(self,
                    bootdev,
                    persist=False,
                    uefiboot=False,
                    callback=None,
                    callback_args=None):
        """Set boot device to use on next reboot

        :param bootdev:
                        *net -- Request network boot
                        *hd -- Boot from hard drive
                        *optical -- boot from CD or DVD drive
                        *setup -- Boot into setup utility
                        *default -- remove any IPMI directed boot device request
        :param persist: If true, ask that system firmware use this device beyond
                        next boot.  Be aware many systems do not honor this
        :param uefiboot: If true, request UEFI boot explicitly.  Strictly
                         speaking, the spec sugests that if not set, the system
                         should BIOS boot and offers no "don't care" option.
                         In practice, this flag not being set does not preclude
                         UEFI boot on any system I've encountered.
        :param callback: optional callback
        :param callback_args: optional arguments to callback 
        :returns: dict or True -- If callback is not provided, the response
        """

        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        if bootdev not in boot_devices:
            _raiseorcall(self.commandcallback,
                        {'error': "Unknown bootdevice %s requested"%bootdev},
                        self.commandcallbackargs)
        self.bootdev=boot_devices[bootdev]
        self.persistboot=persist
        self.uefiboot=uefiboot
        #first, we disable timer by way of set system boot options, 
        #then move on to set chassis capabilities
        self.requestpending=True
        #Set System Boot Options is netfn=0, command=8, data 
        self.ipmi_session.raw_command(netfn=0,
                                      command=8,data=(3,8),
                                      callback=self._bootdev_timer_disabled)
        if callback is None:
            while self.requestpending:
                Session.wait_for_rsp()
            return self.lastresponse

    def _bootdev_timer_disabled(self,response):
        self.requestpending=False
        self.lastresponse=response
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        bootflags=0x80
        if self.uefiboot:
            bootflags = bootflags | 1<<5
        if self.persistboot:
            bootflags = bootflags | 1<<6
        if self.bootdev==0:
            bootflags=0
        data=(5,bootflags,self.bootdev,0,0,0)
        self.ipmi_session.raw_command(netfn=0,
                                      command=8,
                                      data=data,
                                      callback=self.commandcallback,
                                      callback_args=self.commandcallbackargs)
        
    def raw_command(self,
                    netfn,
                    command,
                    data=(),
                    callback=None,
                    callback_args=None):
        """Send raw ipmi command to BMC

        This allows arbitrary IPMI bytes to be issued.  This is commonly used
        for certain vendor specific commands.

        Example: ipmicmd.raw_command(netfn=0,command=4,data=(5))

        :param netfn: Net function number
        :param command: Command value
        :param data: Command data as a tuple or list
        :param callback: optional callback
        :param callback_args: optional arguments to callback 
        :returns: dict or True -- If callback is not provided, the response
        """
        response=self.ipmi_session.raw_command(netfn=0,
                                               command=1,
                                               callback=callback,
                                               callback_args=callback_args)
        if response: #this means there was no callback
            if 'error' in response:
                raise Exception(response['error'])
            return response
    def _got_bootdev(self,response):
        #interpret response per 'get system boot options'
        self.requestpending=False
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        #this should only be invoked for get system boot option complying to 
        #ipmi spec and targeting the 'boot flags' parameter
        assert (response['command'] == 9 and 
                response['netfn'] == 1 and 
                response['data'][0]==1 and 
                (response['data'][1]&0b1111111)==5)
        if (response['data'][1] & 0b10000000 or 
            not response['data'][2] & 0b10000000):
            self.lastresponse={ 'bootdev': 'default' }
        else: #will consult data2 of the boot flags parameter for the data
            bootnum = (response['data'][3] & 0b111100) >> 2
            bootdev = boot_devices[bootnum]
            if (bootdev):
                self.lastresponse={'bootdev': bootdev}
            else:
                self.lastresponse={'bootdev': bootnum}
        if self.commandcallback:
            call_with_optional_args(self.commandcallback,
                                    self.lastresponse,
                                    self.commandcallbackargs)
        
    def get_power(self,callback=None,callback_args=None):
        """
        Get current power state of the managed system

        The response, if successful, should contain 'powerstate' key and 
        either 'on' or 'off' to indicate current state.

        :param callback: optional callback
        :param callback_args: optional arguments to callback 
        :returns: dict or True -- If callback is not provided, the response
        """
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        self.ipmi_session.raw_command(netfn=0,
                                      command=1,
                                      callback=self._got_power)
        return self._waitifsync()

    def _got_power(self,response):
        self.requestpending=False
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        assert(response['command'] == 1 and response['netfn'] == 1)
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        self.lastresponse={'powerstate': self.powerstate}
        if self.commandcallback:
            call_with_optional_args(self.commandcallback,
                                    self.lastresponse,
                                    self.commandcallbackargs)
        
if __name__ == "__main__":
    import sys
    import os
    ipmicmd = ipmi_command(bmc=sys.argv[1],
                           userid=sys.argv[2],
                           password=os.environ['IPMIPASS'])
    print ipmicmd.get_power()
    print ipmicmd.set_power('on',wait=True)
    print ipmicmd.get_bootdev()
    print ipmicmd.set_bootdev('network')
    print ipmicmd.get_bootdev()
    print ipmicmd.set_bootdev('default')
    print ipmicmd.get_bootdev()
