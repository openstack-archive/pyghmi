#!/usr/bin/env python
# This represents the low layer message framing portion of IPMI
import select
import Crypto
import socket
from struct import pack, unpack
from ipmi_constants import payload_types
from random import random

initialtimeout = 0.5 #minimum timeout for first packet to retry in any given session.  This will be randomized to stagger out retries in case of congestion

class IPMISession:
    poller=select.poll()
    bmc_handlers={}
    sessions_waiting={}
    peeraddr_to_nodes={}
    def _createsocket(self):
        IPMISession.socket = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) #INET6 can do IPv4 if you are nice to it
        try: #we will try to fixup our receive buffer size if we are smaller than allowed.  
            maxmf = open("/proc/sys/net/core/rmem_max")
            rmemmax = int(maxmf.read())
            rmemmax = rmemmax/2
            curmax=IPMISession.socket.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
            curmax = curmax/2
            if (rmemmax > curmax):
                IPMISession.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,rmemmax)
        except:
            pass
        curmax=IPMISession.socket.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        curmax = curmax/2
        #we throttle such that we never have no more outstanding packets than our receive buffer should be able to handle
        IPMISession.maxpending=curmax/1000 #pessimistically assume 1 kilobyte messages, way larger than almost all ipmi datagrams
        #for faster performance, sysadmins may want to examine and tune /proc/sys/net/core/rmem_max up.  This allows the module to request more,
        #but does not increase buffers for applications that do less creative things
        #TODO: perhaps spread sessions across a socket pool when rmem_max is small, still get ~65/socket, but avoid long queues that might happen with
        #low rmem_max and putting thousands of nodes in line
    def __init__(self,bmc,userid,password,port=623):
        self.bmc=bmc
        self.userid=userid
        self.password=password
        self.port=port
        if not hasattr(IPMISession,'socket'):
            self._createsocket()
        self.login()
    def _initsession(self):
        self.sessioncontext=0
        self.sequencenumber=0
        self.sessionid=0
        self.authtype=0
        self.ipmiversion=1.5
        self.timeout=initialtimeout+(0.5*random())
        self.seqlun=0
        self.rqaddr=0x81 #per IPMI table 5-4, software ids in the ipmi spec may be 0x81 through 0x8d.  We'll stick with 0x81 for now, do not forsee a reason to adjust
        self.logged=0
        self.sockaddr=None #when we confirm a working sockaddr, put it here to skip getaddrinfo
        self.tabooseq={} #this tracks netfn,command,seqlun combinations that were retried so that 
                         #we don't loop around and reuse the same request data and cause potential ambiguity in return
        self.ipmi15only=0 #default to supporting ipmi 2.0.  Strictly by spec, this should gracefully be backwards compat, but some 1.5 implementations checked reserved bits
    def _checksum(self,*data): #Two's complement over the data
        csum=sum(data)
        csum=csum^0xff
        csum+=1 
        csum &= 0xff
        return csum

    '''
        This function generates the core ipmi payload that would be applicable for any channel (including KCS)
    '''
    def _make_ipmi_payload(self,netfn,command,data=()):
        self.expectedcmd=command
        self.expectednetfn=netfn
        seqincrement=7 #IPMI spec forbids gaps bigger then 7 in seq number.  Risk the taboo rather than violate the rules
        while (netfn,command,self.seqlun) in self.tabooseq and self.tabooseq[(netfn,command,self.seqlun)] and seqincrement:
            self.tabooseq[(netfn,command,self.seqlun)]-=1 #Allow taboo to eventually expire after a few rounds
            self.seqlun += 4 #the last two bits are lun, so add 4 to add 1
            self.seqlun &= 0xff #we only have one byte, wrap when exceeded
            seqincrement-=1
        header=[0x20,netfn<<2] #figure 13-4, first two bytes are rsaddr and netfn, rsaddr is always 0x20 since we are addressing BMC
        reqbody=[self.rqaddr,self.seqlun,command]+list(data)
        headsum=self._checksum(*header)
        bodysum=self._checksum(*reqbody)
        payload=header+[headsum]+reqbody+[bodysum]
        return payload

    def _send_ipmi_net_payload(self,netfn,command,data):
        ipmipayload=self._make_ipmi_payload(netfn,command,data)
        payload_type = payload_types['ipmi']
        if hasattr(self,"integrity_algorithm"):
            payload_type |=  0b01000000
        if hasattr(self,"confidentiality_algorithm"):
            payload_type |=  0b10000000
        self._pack_payload(payload=ipmipayload,type=payload_type)
    def _pack_payload(self,payload=None,type=None):
        if payload is None:
            payload=self.lastpayload
        if type is None:
            type=self.lasttype
        message = [0x6,0,0xff,0x07] #constant RMCP header for IPMI
        baretype = type & 0b00111111
        self.lastpayload=payload
        self.lasttype=type
        message.append(self.authtype)
        if (self.ipmiversion == 2.0):
            message.append(type)
            if (type == 2):
                pass #TODO: OEM payloads, currently not supported
            message += unpack("!4B",pack("!I",self.sessionid))
        message += unpack("!4B",pack("!I",self.sequencenumber))
        if (self.ipmiversion == 1.5):
            message += unpack("!4B",pack("!I",self.sessionid))
            if not self.authtype == 0:
                self._ipmi15authcode(payload)
            message.append(len(payload))
            message += payload
        elif self.ipmiversion == 2.0:
            pass
            #TODO: ipmi 2.0
        self.netpacket = pack("!%dB"%len(message),*message)
        self._xmit_packet()

    def _ipmi15authcode(self,*payload):
        pass #TODO
    def _got_channel_auth_cap(self):
        pass


        
    def _get_channel_auth_cap(self):
        self.callback=self._got_channel_auth_cap
        if (self.ipmi15only):
            self._send_ipmi_net_payload(netfn=0x6,command=0x38,data=[0x0e,0x04])
        else:
            self._send_ipmi_net_payload(netfn=0x6,command=0x38,data=[0x8e,0x04])
    def login(self):
        self._initsession()
        self._get_channel_auth_cap()
    def _xmit_packet(self):
        if self.sockaddr:
            return
        for res in socket.getaddrinfo(self.bmc,self.port,0,socket.SOCK_DGRAM):
            sockaddr = res[4]
            if (res[0] == socket.AF_INET): #convert the sockaddr to AF_INET6
                newhost='::ffff:'+sockaddr[0]
                sockaddr = (newhost,sockaddr[1])
            IPMISession.socket.sendto(self.netpacket,sockaddr)

if __name__ == "__main__":
    ipmis = IPMISession(bmc="10.240.181.1",userid="USERID",password="Passw0rd")
