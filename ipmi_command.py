# Copyright 2013 IBM Corp.
from ipmi_session import ipmi_session, call_with_optional_args
def _raiseorcall(callback,response,args=None):
    if callback is None:
        if 'error' in response:
            raise Exception(response['error'])
    else:
        call_with_optional_args(callback,args)

class ipmi_command:
    def __init__(self,bmc,userid,password,kg=None):
        self.ipmi_session=ipmi_session(bmc=bmc,userid=userid,password=password,kg=kg)
    def set_bootdev(self,bootdev,callback=None,callback_args=None):
        self.commandcallback=callback
        self.commandcallbackargs=callback_args
        #first, we disable timer by way of set system boot options, then move on to set chassis capabilities
        self.requestpending=True
        self.ipmi_session.raw_command(netfn=0,command=8,data=(3,8),callback=self._bootdev_timer_disabled)
        if callback is None:
            while self.requestpending:
                ipmi_session.wait_for_rsp()
            return self.lastresponse

    def _bootdev_timer_disabled(self,response):
        self.requestpending=False
        self.lastresponse=response
        if 'error' in response:
            _raiseorcall(self.commandcallback,response)
            return
        
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
