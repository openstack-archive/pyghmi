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
    
class ipmi_command:
    def __init__(self,bmc,userid,password,kg=None):
        self.ipmi_session=ipmi_session(bmc=bmc,userid=userid,password=password,kg=kg)
    def get_bootdev(self,callback=None,callback_args=None):
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        self.requestpending=True
        self.ipmi_session.raw_command(netfn=0,command=9,data=(5,0,0),callback=self._got_bootdev)
        if callback is None:
            while self.requestpending:
                ipmi_session.wait_for_rsp()
            return self.lastresponse
        
    def set_bootdev(self,bootdev,callback=None,callback_args=None,persist=None,uefiboot=None):
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
        response=self.ipmi_session.raw_command(netfn=0,command=1,callback=callback,callback_args=callback_args)
        if response: #this means there was no callback
            if 'error' in response:
                raise Exception(response['error'])
            if response['data'][0]&1:
                return {'powerstate': 'on' }
            else:
                return {'powerstate': 'on' }
if __name__ == "__main__":
    import sys
    import os
    ipmicmd = ipmi_command(bmc=sys.argv[1],userid=sys.argv[2],password=os.environ['IPMIPASS'])
    print ipmicmd.get_power()
    print ipmicmd.get_bootdev()
    print ipmicmd.set_bootdev('network')
    print ipmicmd.get_bootdev()
    print ipmicmd.set_bootdev('default')
    print ipmicmd.get_bootdev()
