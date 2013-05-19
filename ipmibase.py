#!/usr/bin/env python
# This represents the low layer message framing portion of IPMI
import select
import Crypto
import socket
from collections import deque
from time import time
from hashlib import md5
from struct import pack, unpack
from ipmi_constants import payload_types, ipmi_completion_codes, command_completion_codes
from random import random

initialtimeout = 0.5 #minimum timeout for first packet to retry in any given session.  This will be randomized to stagger out retries in case of congestion

'''
In order to simplify things, in a number of places there is a callback facility and optional arguments to pass in.
An OO oriented caller may find the additional argument needless. Allow them to ignore it by skipping the argument if None
'''
def _call_with_optional_args(callback,*args):
    newargs=[]
    for arg in args:
        if arg is not None:
            newargs.append(arg)
    callback(*newargs)
def get_ipmi_error(response,suffix=""):
    if 'error' in response:
        return response['error']+suffix
    code = response['code']
    command = response['cmd']
    if code == 0:
        return False
    if command in command_completion_codes and code in command_completion_codes[command]:
        return command_completion_codes[command][code]+suffix
    elif code in ipmi_completion_codes:
        return ipmi_completion_codes[code]+suffix
    else:
        return "Unknown code "+code+" encountered"

class IPMISession:
    poller=select.poll()
    bmc_handlers={}
    waiting_sessions={}
    peeraddr_to_nodes={}
    @classmethod
    def _createsocket(cls):
        cls.socket = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) #INET6 can do IPv4 if you are nice to it
        try: #we will try to fixup our receive buffer size if we are smaller than allowed.  
            maxmf = open("/proc/sys/net/core/rmem_max")
            rmemmax = int(maxmf.read())
            rmemmax = rmemmax/2
            curmax=cls.socket.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
            curmax = curmax/2
            if (rmemmax > curmax):
                cls.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,rmemmax)
        except:
            pass
        curmax=cls.socket.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        cls.poller.register(cls.socket,select.POLLIN)
        curmax = curmax/2
        #we throttle such that we never have no more outstanding packets than our receive buffer should be able to handle
        cls.pending=0
        cls.maxpending=curmax/1000 #pessimistically assume 1 kilobyte messages, way larger than almost all ipmi datagrams
        #for faster performance, sysadmins may want to examine and tune /proc/sys/net/core/rmem_max up.  This allows the module to request more,
        #but does not increase buffers for applications that do less creative things
        #TODO: perhaps spread sessions across a socket pool when rmem_max is small, still get ~65/socket, but avoid long queues that might happen with
        #low rmem_max and putting thousands of nodes in line
    '''
    This function handles the synchronous caller case in liue of a client provided callback
    '''
    def _sync_login(self,response):
        if 'error' in response:
            raise Exception(response['error'])

    def __init__(self,bmc,userid,password,port=623,onlogon=None,onlogonargs=None):
        self.bmc=bmc
        self.userid=userid
        self.password=password
        self.port=port
        self.onlogonargs=onlogonargs
        if (onlogon is None):
            self.async=False
            self.onlogon=self._sync_login
        else:
            self.async=True
            self.onlogon=onlogon
        if not hasattr(IPMISession,'socket'):
            self._createsocket()
        self.login()
        if not self.async:
            while not self.logged:
                IPMISession.wait_for_rsp()
    def _initsession(self):
        self.ipmicallback=None
        self.ipmicallbackargs=None
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
        self.ipmi15only=1 #default to supporting ipmi 2.0.  Strictly by spec, this should gracefully be backwards compat, but some 1.5 implementations checked reserved bits
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
        self.expectednetfn=netfn+1 #in ipmi, the response netfn is always one higher than the request payload, we assume we are always the
                                   #requestor for now
        seqincrement=7 #IPMI spec forbids gaps bigger then 7 in seq number.  Risk the taboo rather than violate the rules
        while (netfn,command,self.seqlun) in self.tabooseq and self.tabooseq[(netfn,command,self.seqlun)] and seqincrement:
            self.tabooseq[(self.expectednetfn,command,self.seqlun)]-=1 #Allow taboo to eventually expire after a few rounds
            self.seqlun += 4 #the last two bits are lun, so add 4 to add 1
            self.seqlun &= 0xff #we only have one byte, wrap when exceeded
            seqincrement-=1
        header=[0x20,netfn<<2] #figure 13-4, first two bytes are rsaddr and netfn, rsaddr is always 0x20 since we are addressing BMC
        reqbody=[self.rqaddr,self.seqlun,command]+list(data)
        headsum=self._checksum(*header)
        bodysum=self._checksum(*reqbody)
        payload=header+[headsum]+reqbody+[bodysum]
        return payload

    def _generic_callback(self,response):
        errorstr = get_ipmi_error(response)
        if errorstr:
            response['error']=errorstr
        self.lastresponse=response
    def raw_command(self,netfn,command,data=[],callback=None,callback_args=None):
        self.ipmicallbackargs=callback_args
        if callback is None:
            self.lastresponse=None
            self.ipmicallback=self._generic_callback
        else:
            self.ipmicallback=callback
        self._send_ipmi_net_payload(netfn,command,data)
        if callback is None:
            while self.lastresponse is None:
                IPMISession.wait_for_rsp()
            return self.lastresponse
    def _send_ipmi_net_payload(self,netfn,command,data):
        ipmipayload=self._make_ipmi_payload(netfn,command,data)
        payload_type = payload_types['ipmi']
        if hasattr(self,"integrity_algorithm"):
            payload_type |=  0b01000000
        if hasattr(self,"confidentiality_algorithm"):
            payload_type |=  0b10000000
        self._pack_payload(payload=ipmipayload,payload_type=payload_type)
    def _pack_payload(self,payload=None,payload_type=None):
        if payload is None:
            payload=self.lastpayload
        if payload_type is None:
            payload_type=self.last_payload_type
        message = [0x6,0,0xff,0x07] #constant RMCP header for IPMI
        baretype = payload_type & 0b00111111
        self.lastpayload=payload
        self.last_payload_type=payload_type
        message.append(self.authtype)
        if (self.ipmiversion == 2.0):
            message.append(payload_type)
            if (payload_type == 2):
                pass #TODO: OEM payloads, currently not supported
            message += unpack("!4B",pack("<I",self.sessionid))
        message += unpack("!4B",pack("<I",self.sequencenumber))
        if (self.ipmiversion == 1.5):
            message += unpack("!4B",pack("<I",self.sessionid))
            if not self.authtype == 0:
                message += self._ipmi15authcode(payload)
            message.append(len(payload))
            message += payload
            totlen=34+len(message) #Guessing the ipmi spec means the whole packet ande assume no tag in old 1.5 world
            if (totlen in (56,84,112,128,156)):
                message.append(0) #Legacy pad as mandated by ipmi spec
        elif self.ipmiversion == 2.0:
            pass
            #TODO: ipmi 2.0
        self.netpacket = pack("!%dB"%len(message),*message)
        self._xmit_packet()

    def _ipmi15authcode(self,payload,checkremotecode=False):
        if self.authtype == 0: #Only for things prior to auth in ipmi 1.5, not like 2.0 cipher suite 0
            return ()
        password = self.password
        padneeded = 16 - len(password)
        if padneeded < 0:
            raise Exception("Password is too long for ipmi 1.5")
        password += '\x00'*padneeded
        passdata = unpack("16B",password)
        if checkremotecode:
            seqbytes = unpack("!4B",pack("<I",self.remotesequencenumber))
        else:
            seqbytes = unpack("!4B",pack("<I",self.sequencenumber))
        sessdata = unpack("!4B",pack("<I",self.sessionid))
        bodydata = passdata + sessdata + tuple(payload) + seqbytes + passdata
        dgst = md5(pack("%dB"%len(bodydata),*bodydata)).digest()
        hashdata = unpack("!%dB"%len(dgst),dgst)
        return hashdata

    def _got_channel_auth_cap(self,response):
        if 'error' in response:
            _call_with_optional_args(self.onlogon,response,self.onlogonargs)
            return
        if response['code'] == 0xcc and self.ipmi15only is not None: #tried ipmi 2.0 against a 1.5 which should work, but some bmcs thought 'reserved' meant 'must be zero'
            self.ipmi15only=1
            return self._get_channel_auth_cap()
        errstr = get_ipmi_error(response,suffix=" while trying to get channel authentication capabalities")
        if errstr:
            _call_with_optional_args(self.onlogon,{'error': errstr},self.onlogonargs)
            return
        data = response['data']
        self.currentchannel=data[0]
        if data[1] & 0b10000000 and data[3] & 0b10: #those two bits together indicate ipmi 2.0 support
            self.ipmiversion=2.0
        if self.ipmiversion == 1.5:
            if not (data[1] & 0b100):
                _call_with_optional_args(self.onlogon,{'error': "MD5 is required but not enabled or available on target BMC"},self.onlogonargs)
                return
            self._get_session_challenge()
        elif self.ipmiversion == 2.0:
            self._open_rmcpplus_request()
        
    def _got_session_challenge(self,response):
        errstr=get_ipmi_error(response,suffix=" while getting session challenge")
        if errstr:
            _call_with_optional_args(self.onlogon,{'error':errstr},self.onlogonargs)
            return
        data = response['data']
        self.sessionid=unpack("<I",pack("4B",*data[0:4]))[0]
        self.authtype=2 
        self._activate_session(data[4:])
    '''
    This sends the activate session payload.  We pick '1' as the requested sequence number without perturbing our real sequence number
    '''
    def _activate_session(self,data):
        rqdata = [2,4]+list(data)+[1,0,0,0]; #TODO: this always requests admin level, this could be toned down, but maybe 2.0 is the answer
        self.ipmicallback=self._activated_session
        self._send_ipmi_net_payload(netfn=0x6,command=0x3a,data=rqdata)

    def _activated_session(self,response):
        errstr = get_ipmi_error(response)
        if errstr:
            _call_with_optional_args(self.onlogon,{'error':errstr},self.onlogonargs)
            return
        data=response['data']
        self.sessionid=unpack("<I",pack("4B",*data[1:5]))[0]
        self.sequencenumber=unpack("<I",pack("4B",*data[5:9]))[0]
        self.privlevel=4 #ipmi 1.5 we are going to settle for nothing less than administrator for now
        self._req_priv_level()
    def _req_priv_level(self):
        self.ipmicallback=self._got_priv_level
        self._send_ipmi_net_payload(netfn=0x6,command=0x3b,data=[self.privlevel])
    def _got_priv_level(self,response):
        errstr=get_ipmi_error(response,suffix=" while requesting privelege level %d for %s"%(self.privlevel,self.userid))
        if errstr:
            _call_with_optional_args(self.onlogon,{'error': errstr},self.onlogonargs)
            return
        self.logged=1
        _call_with_optional_args(self.onlogon,{'success':True},self.onlogonargs)

    def _get_session_challenge(self):
        reqdata=[2]
        if len(self.userid) > 16:
            raise Exception("Username too long for IPMI, must not exceed 16")
        padneeded=16-len(self.userid)
        userid=self.userid+('\x00'*padneeded)
        reqdata += unpack("!16B",userid)
        self.ipmicallback=self._got_session_challenge
        self._send_ipmi_net_payload(netfn=0x6,command=0x39,data=reqdata)

    def _open_rmcpplus_request(self):
        raise Exception("TODO: implement ipmi 2.0")
    def _get_channel_auth_cap(self):
        self.ipmicallback=self._got_channel_auth_cap
        if (self.ipmi15only):
            self._send_ipmi_net_payload(netfn=0x6,command=0x38,data=[0x0e,0x04])
        else:
            self._send_ipmi_net_payload(netfn=0x6,command=0x38,data=[0x8e,0x04])
    def login(self):
        self._initsession()
        self._get_channel_auth_cap()
    @classmethod
    def wait_for_rsp(cls,timeout=None):
        curtime=time()
        for session,parms in cls.waiting_sessions.iteritems():
            if timeout==0:
                break
            if parms['timeout'] <= curtime:
                timeout=0 #exit after one guaranteed pass
            if timeout is not None and timeout < parms['timeout']-curtime:
                continue #timeout is smaller than the current session would need
            timeout = parms['timeout']-curtime #set new timeout value
        if timeout is None:
            return len(cls.waiting_sessions)
        if cls.poller.poll(timeout*1000):
            while cls.poller.poll(0): #if the somewhat lengthy queue processing takes long enough for packets to come in, be eager
                pktqueue=deque([])
                while cls.poller.poll(0): #looks rendundant, but want to queue and process packets to keep things of RCVBUF
                    rdata=cls.socket.recvfrom(3000)
                    pktqueue.append(rdata)
                while len(pktqueue):
                    (data,sockaddr)=pktqueue.popleft()
                    cls._route_ipmiresponse(sockaddr,data)
                    while cls.poller.poll(0): #seems ridiculous, but between every single callback, check for packets again
                        rdata=cls.socket.recvfrom(3000)
                        pktqueue.append(rdata)
        sessionstodel=[]
        for session,parms in cls.waiting_sessions.iteritems():
            if parms['timeout'] < curtime: #timeout has expired, time to give up on it and trigger timeout response in the respective session
                sessionstodel.append(session) #defer deletion until after loop as to avoid confusing the for loop
                cls.pending -= 1
                session._timedout()
        for session in sessionstodel:
            del cls.waiting_sessions[session]
        return len(cls.waiting_sessions)
    @classmethod
    def _route_ipmiresponse(cls,sockaddr,data):
        if not (data[0] == '\x06' and data[2:4] == '\xff\x07'): #packed data is not ipmi
            return
        try:
            cls.bmc_handlers[sockaddr]._handle_ipmi_packet(data)
            cls.pending-=1
        except KeyError:
            pass
    def _handle_ipmi_packet(self,data):
        if data[4] in ('\x00','\x02'): #This is an ipmi 1.5 paylod
            remsequencenumber = unpack('<I',data[5:9])[0]
            if hasattr(self,'remsequencenumber') and remsequencenumber < self.remsequencenumber:
                return -5 # remote sequence number is too low, reject it
            self.remsequencenumber=remsequencenumber
            if ord(data[4]) != self.authtype:
                return -2 #BMC responded with mismatch authtype, for the sake of mutual authentication reject it. If this causes legitimate issues, it's the vendor's fault
            remsessid = unpack("<I",data[9:13])[0] 
            if remsessid != self.sessionid:
                return -1 #does not match our session id, drop it
            #new we need a mutable representation of the packet, rather than copying pieces of the packet over and over
            rsp=list(unpack("!%dB"%len(data),data))
            authcode=0
            if rsp[4] == 2: # we have an authcode in this ipmi 1.5 packet...
                authcode=rsp[13:29]
                del rsp[13:29]
            payload=list(rsp[14:14+rsp[13]])
            self._parse_ipmi_payload(payload)
                


    def _parse_ipmi_payload(self,payload):
        #For now, skip the checksums since we are in LAN only, TODO: if implementing other channels, add checksum checks here
        if not (payload[4] == self.seqlun and payload[1]>>2 == self.expectednetfn and payload[5] == self.expectedcmd):
            return -1 #this payload is not a match for our outstanding ipmi packet
        if hasattr(self,'hasretried') and self.hasretried:
            self.hasretried=0
            self.tabooseq[(self.expectednetfn,self.expectedcmd,self.seqlun)]=16 # try to skip it for at most 16 cycles of overflow
        #We want to now remember that we do not have an expected packet
        self.expectednetfn=0x1ff #bigger than one byte means it can never match
        self.expectedcmd=0x1ff
        self.seqlun += 4 #prepare seqlun for next transmit
        self.seqlun &= 0xff #when overflowing, wrap around
        del IPMISession.waiting_sessions[self]
        self.lastpayload=None #render retry mechanism utterly incapable of doing anything, though it shouldn't matter
        self.last_payload_type=None
        del payload[0:5] # remove header of rsaddr/netfn/lun/checksum/rq/seq/lun
        del payload[-1] # remove the trailing checksum
        response={}
        response['cmd']=payload[0]
        response['code']=payload[1]
        del payload[0:2]
        response['data']=payload
        self.timeout=initialtimeout+(0.5*random())
        if self.ipmicallbackargs is not None:
            args=(response,self.ipmicallbackargs)
        else:
            args=(response,)
        self.ipmicallback(*args)

    def _timedout(self):
        #TODO: retransmit and error handling on lost packets
        pass
        
    def _xmit_packet(self,waitforpending=True):
        if waitforpending:
            IPMISession.wait_for_rsp(timeout=0) #take a convenient opportunity to drain the socket queue if applicable
            while IPMISession.pending > IPMISession.maxpending:
                IPMISession.wait_for_rsp()
        IPMISession.waiting_sessions[self]={}
        IPMISession.waiting_sessions[self]['ipmisession']=self
        IPMISession.waiting_sessions[self]['timeout']=self.timeout+time()
        IPMISession.pending+=1
        if self.sockaddr:
            IPMISession.socket.sendto(self.netpacket,self.sockaddr)
        else: #he have not yet picked a working sockaddr for this connection, try all the candidates that getaddrinfo provides
            for res in socket.getaddrinfo(self.bmc,self.port,0,socket.SOCK_DGRAM):
                sockaddr = res[4]
                if (res[0] == socket.AF_INET): #convert the sockaddr to AF_INET6
                    newhost='::ffff:'+sockaddr[0]
                    sockaddr = (newhost,sockaddr[1],0,0)
                IPMISession.bmc_handlers[sockaddr]=self
                IPMISession.socket.sendto(self.netpacket,sockaddr)
        if self.sequencenumber: #seq number of zero will be left alone as it is special, otherwise increment
            self.sequencenumber += 1
    def logout(self,callback=None,callback_args=None):
        if not self.logged:
            if callback is None:
                return {'success': True }
            callback({'success': True })
            return
        self.noretry=1 #risk open sessions if logout request gets dropped, logout is not idempotent so this is the better bet
        self.raw_command(command=0x3c,netfn=6,data=unpack("4B",pack("I",self.sessionid)),callback=callback,callback_args=callback_args)
        self.logged=0
        if callback is None:
            return {'success': True }
        callback({'success': True })


if __name__ == "__main__":
    ipmis = IPMISession(bmc="10.240.181.1",userid="USERID",password="Passw0rd")
    print ipmis.raw_command(command=2,data=[1],netfn=0)
    ipmis.logout()
