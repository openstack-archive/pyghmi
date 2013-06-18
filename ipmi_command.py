# Copyright 2013 IBM Corp.
"""
@author: Jarrod Johnson
"""
from ipmi_session import ipmi_session, call_with_optional_args
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
    "boot": -1, #not a valid direct boot state, but here for convenience of 'in' statement
}
    
class ipmi_command(object):
    """
    Send IPMI commands to BMCs.

    Args:
        * bmc (str): hostname or ip address of the BMC
        * userid (str): username to use to connec
        * password (str): password to connect to the BMC
        * kg (str): Optional parameter to use if BMC has a particular Kg configured
    """
    def __init__(self,bmc,userid,password,kg=None):
        """
        Establish a new IPMI session.
        """
        #TODO: accept tuples and lists of each parameter for mass operations without pushing the async complexities up the stack
        self.ipmi_session=ipmi_session(bmc=bmc,userid=userid,password=password,kg=kg)
    def get_bootdev(self,callback=None,callback_args=None):
        """
        Get current boot device override information.

        Args:
            * callback (function): optional callback if async behavior desired
            * callback_args (tuple): optional arguments to callback 
        """
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        self.ipmi_session.raw_command(netfn=0,command=9,data=(5,0,0),callback=self._got_bootdev)
        return self._waitifsync()
    def _waitifsync(self):
        self.requestpending=True
        if self.commandcallback is None:
            while self.requestpending:
                ipmi_session.wait_for_rsp()
            return self.lastresponse
        return True
        
    '''
    powerstate argument is one of:
    on - request system turn on, do nothing if already on
    off - rudely turn system power off, regardless of OS/firmware state, do nothing if off
    reset - request immediate system reset without regard for OS/firmware state, do nothing if off
    boot - if target is on, reset, if target is off, turn on
    softoff - request graceful shutdown from OS, no guarantee that system will turn off.
    '''
    def set_power(self,powerstate,callback=None,callback_args=None,wait=False):
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        if powerstate not in power_states:
            _raiseorcall(self.commandcallback,{'error': "Unknown power state %s requested"%powerstate},self.commandcallbackargs)
        self.newpowerstate=powerstate
        self.wait_for_power=wait
        self.ipmi_session.raw_command(netfn=0,command=1,callback=self._set_power_with_chassis_info)
        return self._waitifsync()
    def _set_power_with_chassis_info(self,response):
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        if self.newpowerstate=='boot':
            self.newpowerstate = 'on' if self.powerstate=='off' else 'reset'
        self.ipmi_session.raw_command(netfn=0,command=2,data=[power_states[self.newpowerstate]],callback=self._power_set)

    def _power_set(self,response):
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        self.lastresponse={'pendingpowerstate': self.newpowerstate}
        if self.wait_for_power and self.newpowerstate in ('on','off','softoff'):
            if self.newpowerstate=='softoff':
                self.waitpowerstate='off'
            else:
                self.waitpowerstate=self.newpowerstate
            self.ipmi_session.raw_command(netfn=0,command=1,callback=self._power_wait)
        else:
            self.requestpending=False
            if self.commandcallback:
                call_with_optional_args(self.commandcallback,self.lastresponse,self.commandcallbackargs)

    def _power_wait(self,response):
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        self.powerstate = 'on' if (response['data'][0] & 1) else 'off'
        if self.powerstate==self.waitpowerstate:
            self.requestpending=False
            self.lastresponse={'powerstate': self.powerstate}
            if self.commandcallback:
                call_with_optional_args(self.commandcallback,self.lastresponse,self.commandcallbackargs)
            return
        self.ipmi_session.raw_command(netfn=0,command=1,callback=self._power_wait)
            


    def set_bootdev(self,bootdev,callback=None,callback_args=None,persist=False,uefiboot=False):
        """
        Set boot device to use on next reboot

        Args:
            * bootdev (str): One of 'pxe', 'hd', 'dvd', 'setup', 'default'
            * callback (function): Optional callback for async operation
            * callback_args (tuple): Optional arguments for callback (probably needless if callback is an instance method of an object)
            * persist (bool): If set, system firmware may persist the boot device request across multiple resets
            * uefiboot (bool): If set, request explicitly UEFI style boot.
        Example:
            ipmicmd.set_bootdev("pxe")
        """

        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        if bootdev not in boot_devices:
            _raiseorcall(self.commandcallback,{'error': "Unknown bootdevice %s requested"%bootdev},self.commandcallbackargs)
        self.bootdev=boot_devices[bootdev]
        self.persistboot=persist
        self.uefiboot=uefiboot
        #first, we disable timer by way of set system boot options, then move on to set chassis capabilities
        self.requestpending=True
        #Set System Boot Options is netfn=0, command=8, data 
        self.ipmi_session.raw_command(netfn=0,command=8,data=(3,8),callback=self._bootdev_timer_disabled)
        if callback is None:
            while self.requestpending:
                ipmi_session.wait_for_rsp()
            return self.lastresponse

    def _bootdev_timer_disabled(self,response):
        self.requestpending=False
        self.lastresponse=response
        if 'error' in response:
            _raiseorcall(self.commandcallback,response,self.commandcallbackargs)
            return
        bootflags=0x80
        if self.uefiboot: #frustrating, there is no 'default', and this is generally not honored...
            bootflags = bootflags | 1<<5
        if self.persistboot: #another flag that is oft silently ignored
            bootflags = bootflags | 1<<6
        if self.bootdev==0:
            bootflags=0
        data=(5,bootflags,self.bootdev,0,0,0)
        self.ipmi_session.raw_command(netfn=0,command=8,data=data,callback=self.commandcallback,callback_args=self.commandcallbackargs)
        
    def raw_command(self,netfn,command,data=(),callback=None,callback_args=None):
        """
        Send raw ipmi information to BMC

        Args:
            * netfn (int): Net function number
            * command (int): Command 
            * data (tuple): Tuple of data bytes to submit
            * callback (function): Optional callback for asynchronous mode.
            * callback_args (tuple): Optional arguments should callback be in use *and* require more data

        Example:
            ipmicmd.raw_command(netfn=0,command=4,data=(5))
        """
        response=self.ipmi_session.raw_command(netfn=0,command=1,callback=callback,callback_args=callback_args)
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
        #this should only be invoked for get system boot option complying to ipmi spec and targeting the 'boot flags' parameter
        assert (response['command'] == 9 and response['netfn'] == 1 and response['data'][0]==1 and (response['data'][1]&0b1111111)==5)
        if (response['data'][1] & 0b10000000 or not response['data'][2] & 0b10000000):
            self.lastresponse={ 'bootdev': 'default' }
        else: #will consult data2 of the boot flags parameter for the data for now
            bootnum = (response['data'][3] & 0b111100) >> 2
            bootdev = boot_devices[bootnum]
            if (bootdev):
                self.lastresponse={'bootdev': bootdev}
            else:
                self.lastresponse={'bootdev': bootnum}
        if self.commandcallback:
            call_with_optional_args(self.commandcallback,self.lastresponse,self.commandcallbackargs)
        
    def get_power(self,callback=None,callback_args=None):
        """
        Get current power state of the BMC device

        Args:
            * callback (function): optional callback to request asynchronous behavior
            * callback_args (tuple): optional arguments for callback
        
        Returns:
            If no callback provided, a dict with 'powerstate' member.
            Otherwise, returns true and the dict is passed as an argument to the provided callback.

        Example:
            ipmicmd.get_power()
        """
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        self.ipmi_session.raw_command(netfn=0,command=1,callback=self._got_power)
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
            call_with_optional_args(self.commandcallback,self.lastresponse,self.commandcallbackargs)
        
if __name__ == "__main__":
    import sys
    import os
    ipmicmd = ipmi_command(bmc=sys.argv[1],userid=sys.argv[2],password=os.environ['IPMIPASS'])
    print ipmicmd.get_power()
    print ipmicmd.set_power('on',wait=True)
    print ipmicmd.get_bootdev()
    print ipmicmd.set_bootdev('network')
    print ipmicmd.get_bootdev()
    print ipmicmd.set_bootdev('default')
    print ipmicmd.get_bootdev()
