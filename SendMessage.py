#coding:utf-8
import socket
import exceptions
import os
import sys
import threading
from collections import namedtuple,defaultdict
from errno import EAGAIN, ECONNRESET, EADDRINUSE, EADDRNOTAVAIL

import time
from mininet.cli import CLI
from mininet.log import setLogLevel, info,error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.node import RemoteController, OVSKernelSwitch,Controller

from connection import *
from mesagestruct import flip
from pox.core import core
from pox.lib.revent import *
from pox.lib.pxpcap.parser import *
from pox.lib.recoco.recoco import *
import pox.openflow.libopenflow_01 as of

log = core.getLogger()
mutex = threading.Lock()

class MininetTask(threading.Thread):
  def __init__ (self, connection):
    threading.Thread.__init__(self)
    self.connection = connection
    self.net=None
    self.rectopolyreply=0
    self.switches = set()
    self.addswitches={}
    self.finallink=[]
    self.addlinks=[]
    self.statuslinks={}
    self.snum=0

    connection.addListeners(self)
    self.start()

  def _handle_MirrorConnectionUp (self, event):
    topolyrequest=mm.mms_states_request()
    topolyrequest.reqtypes=mm.MMSSR_TOPOLY_REQUEST
    #print topolyrequest.show()
    self.connection.send(topolyrequest)

    flowsrequest=mm.mms_states_request()
    flowsrequest.reqtypes=mm.MMSSR_FLOWS_REQUEST
    #print flowsrequest.show()
    self.connection.send(flowsrequest)

  def _handle_TopolyReply (self, event):
    #print event.mms.show()
    mutex.acquire()
    self.finallink=event.mms.links
    for l in self.finallink:
      self.switches.add(l.dpid1)
      self.switches.add(l.dpid2)
    self.rectopolyreply=1
    mutex.release()

  def _handle_FlowsReply(self, event):
    msg = of.ofp_flow_mod()
    msg.match = event.match
    msg.priority = event.priority
    msg.idle_timeout=event.idle_timeout
    msg.hard_timeout=event.hard_timeout
    msg.actions=event.actions
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

  def _handle_PoxConnectionUp(self, event):
    mutex.acquire()
    s=event.mms.dpid
    if self.addswitches.get(s)==None:
      self.snum+=1
      switch = self.net.addSwitch('mirror_s%s'%self.snum,dpid=dpid_to_mininet(s))
      switch.start(self.net.controllers)
      self.addswitches[s]=switch
    mutex.release()

  def _handle_PoxConnectionDown(self, event):
    mutex.acquire()
    s=event.mms.dpid
    if self.addswitches.get(s)!=None:
      self.addswitches[s].stop()
      self.addswitches.pop(s,None)
    mutex.release()

  def createtoptly(self):
    if len(self.addlinks)<len(self.finallink):#add Link
      for s in self.switches:
        if self.addswitches.get(s)==None:#add switch
          #print dpid_to_str(s)
          self.snum+=1
          switch = self.net.addSwitch('mirror_s%s'%self.snum,dpid=dpid_to_mininet(s))
          '''
          if s==10:
            portnum=4
            for h in range(3):
              portnum+=1
              host = self.net.addHost('h%s' % (h + 4))
              self.net.addLink(host, switch,port1=None,port2=portnum)
            self.net.configHosts()
          '''
          #print self.net.controllers,switch
          switch.start(self.net.controllers)
          self.addswitches[s]=switch

      for l in self.finallink:
        if not self.addlinks.count(l) or not self.addlinks.count(flip(l)):
          switch_first=self.addswitches[l.dpid1]
          switch_second=self.addswitches[l.dpid2]
          port_first=l.port1
          port_second=l.port2
          addlink=self.net.addLink(switch_first, switch_second, port_first, port_second)
          switch_first.attach( addlink.intf1 )
          switch_second.attach( addlink.intf2 )
          print addlink.intf2.ifconfig()
          print addlink.intf2.MAC()

          self.addlinks.append(l)
          self.statuslinks[l]=addlink
      return
    if len(self.addlinks)>len(self.finallink):#delete Link
      for l in self.addlinks:
        if not self.finallink.count(l) or not self.finallink.count(flip(l)):
          if self.statuslinks.has_key(l):
            self.statuslinks[l].delete()
            self.statuslinks.pop(l, None)
            self.addlinks.remove(l)
          elif self.statuslinks.has_key(flip(l)):
            linkflip=flip(l)
            self.statuslinks[linkflip].delete()
            self.statuslinks.pop(linkflip, None)
            self.addlinks.remove(linkflip)
      return

  def run (self):
    setLogLevel("info")
    OVSKernelSwitch.setup()#"Make sure Open vSwitch is installed and working"

    info("****creating network****\n")
    self.net = Mininet(listenPort = 6666)

    controller = RemoteController("mirrorController",   ip = "127.0.0.1")
    self.net.addController(controller)
    while core.running:
      try:
        time.sleep(3)
        if not core.running: break
        '''
        self.net.pingAll()
        if len(self.addswitches)!=0:
          for i in self.addswitches:
            print self.addswitches[i].dpctl('show')
        '''
        if self.rectopolyreply==1:
          mutex.acquire()
          self.createtoptly()
          self.rectopolyreply=0
          mutex.release()
      except exceptions.KeyboardInterrupt:
        break
      except:
        log.exception("Exception SendMes running ")
        break
    self.net.stop()

class PCapWriter(object):
  def __init__(self,filename):
    self._isfileopen=False
    self._out=None
    self.filename=filename
    self.buffer = {}
    self.datanum=0


  @property
  def out (self):
    return self._out if self._isfileopen else None
  @out.setter
  def out (self, value):
    self._out=value

  @property
  def filesize (self):
    statinfo=os.stat(self.filename)
    return statinfo.st_size

  @property
  def file_ctime (self):
    statinfo=os.stat(self.filename)
    return time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(statinfo.st_ctime))

  @property
  def isfileopen (self):
    return self._isfileopen

  @isfileopen.setter
  def isfileopen (self, value):
    self._isfileopen=value

  def openfile(self,mode):
    if self._isfileopen==False:
      try:
        self._out=open(self.filename,mode)
      except:
        RuntimeError("open file error")
      self._isfileopen=True

  def writeraw(self,data):
    if self._isfileopen==True and len(self.buffer)==0:
      self.out.write(data)
    elif self._isfileopen==False:
      packed = b""
      packed +=data
      self.buffer[self.datanum]=packed
      self.datanum+=1
    elif self._isfileopen==True and len(self.buffer)!=0:
      for data in self.buffer.itervalues():
        self.out.write(data)
      self.buffer.clear()
      self.datanum=0
    else:
      log.error("PCapWriter writeraw errror")

  def close(self):
    if self._isfileopen==True and len(self.buffer)==0:
      self.out.flush()
      self.out.close()
      self._isfileopen=False
    elif self._isfileopen==True and len(self.buffer)!=0:
      for data in self.buffer.itervalues():
        self.out.write(data)
      self.buffer.clear()
      self.datanum=0
      self.out.flush()
      self.out.close()
      self._isfileopen=False
    elif self._isfileopen==False:
      self.buffer.clear()
      self.datanum=0
    else:
      log.error("PCapWriter close errror")

class PCapFileParser(PCapParser):
  def __init__(self,filename):
    PCapParser.__init__(self)
    self.pcapfilename=filename

  def openfile(self):
    try:
      output = open(self.pcapfilename, "rb")
    except:
      raise RuntimeError("PCapFileParser open file error")
    self._buf=output.read()
    output.close()

  def cb_packettype(self,data, parser):
    msg = ""
    packet = pkt.ethernet(data)
    p = packet
    while p:
      if isinstance(p, basestring):
        buf=p
        offset = 0
        ofp_type = ord(buf[offset+1])
        if ofp_type == of.OFPT_FLOW_MOD:
          msg += "[of bytes:OFPT_FLOW_MOD]"
        elif ofp_type == of.OFPT_PACKET_IN:
          msg += "[of bytes:OFPT_PACKET_IN]"
        elif ofp_type == of.OFPT_PACKET_OUT:
          msg += "[of bytes:OFPT_PACKET_OUT]"
        else:
          msg += "[of bytes:UNKNOWN]"
        break
      msg += "[%s]" % (p.__class__.__name__,)
      p = p.next
    print self._time,msg

  def packettype(self):
    self.openfile()
    self.callback=self.cb_packettype
    self._proc = self._proc_global_header
    self.feed(b'')

  def cb_parserflows(self,data, parser):
    packet = pkt.ethernet(data)
    p = packet
    while p:
      if isinstance(p, basestring):
        buf=p
        buf_len=len(p)
        offset = 0
        ofp_type = ord(buf[offset+1])
        while buf_len - offset > 8:
          msg_length = ord(buf[offset+2]) << 8 | ord(buf[offset+3])

          if buf_len - offset < msg_length: break

          new_offset,msg = unpackers[ofp_type](buf, offset)
          assert new_offset - offset == msg_length
          offset = new_offset
        break
      p = p.next
    print  self._time,msg

  def parserflows(self):
    self.openfile()
    self.callback=self.cb_parserflows
    self._proc = self._proc_global_header
    self.feed(b'')

class MirrorStates(object):
  def __init__(self, connection):
    self.dict_pxpcap = defaultdict(lambda:defaultdict(lambda:[]))
    connection.addListeners(self)
    core.addListeners(self, weak=True)

  def _handle_GoingDownEvent (self, event):
    self.close()

  def close (self):
    mutex.acquire()
    try:
      for file in self.dict_pxpcap.iteritems():
        for name in file:
          pass
        for PCapW in name.itervalues():
          PCapW.close()
    except:
      log.error("PCapW close error")
    self.dict_pxpcap.clear()
    mutex.release()

  def _handle_FileReply (self, event):
    filename=event.mms.filename
    conid=dpid_to_filename(event.mms.dpid,event.mms.port)
    try:
      PcapW=PCapWriter(filename)
      PcapW.openfile("wb")
      self.dict_pxpcap[conid][filename]=PcapW
    except:
      log.error("MirrorStates open file error filename: %s",filename)
    PcapW.writeraw(event.mms.filedata)
    PcapW.out.flush()

  def _handle_PcapMessage (self, event):
    filename=event.mms.filename
    conid=dpid_to_filename(event.mms.dpid,event.mms.port)
    try:
      PcapW = self.dict_pxpcap[conid][filename]
    except:
      log.error("MirrorStates get dict_pxpcap error")
    PcapW.writeraw(event.mms.messagedata)

class SendMesTask(Task):
  def __init__(self, port = 6655, address = '0.0.0.0'):
    Task.__init__(self)
    self.port = int(port)
    self.address = address
    self.connection=None

    #core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)
    core.addListeners(self)

  def _handle_GoingUpEvent (self, event):
    self.start()


  def run(self):
    con = None
    tryconnectnum=0
    while core.running:
      if tryconnectnum==3:
        raise RuntimeError("Error on RecMessage.py can't connect service")
        core.quit()
      clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      try:
        clientsock.connect((self.address, self.port))
      except socket.error as (errno, strerror):
      #except Exception as error:
        #raise Exception, str(error)
        log.error("Error %i while connect socket: %s", errno, strerror)
        clientsock.close()
        time.sleep(2)
        tryconnectnum+=1
        continue
      tryconnetcnum=0
      self.connection=Connection(clientsock)
      #new_con=Connection(clientsock)
      #time.sleep(1)
      MininetTask(self.connection)
      hellomessage=mm.mms_hello()
      mirrorstatse=MirrorStates(self.connection)
      core.register("mirrorstatse", mirrorstatse)
      self.connection.send(hellomessage)
      #self.connection.addListeners(self)
      try:
        while True:
          con = None
          rlist, wlist, elist = yield Select([self.connection], [], [self.connection], 5)
          if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
            if not core.running: break

          if len(elist)!=0:
            raise RuntimeError("Error on RecMessage.py listener socket")

          if len(rlist)!=0:
            timestamp = time.time()
            self.connection.idle_time = timestamp
            if self.connection.read() is False:
              self.connection.close()
              #print 'begin recv'
              #data = con.recv(2048)
              #con.close()
            #else:
              #hellomessage=mm.mms_hell()
              #new_con.send(hellomessage)
              #mutex.acquire()

              #self.receivelinkevent=0;
              #print self.receivelinkevent

              #mutex.release()
      except exceptions.KeyboardInterrupt:
        break
      except:
        doTraceback = True
        if sys.exc_info()[0] is socket.error:
          if sys.exc_info()[1][0] == ECONNRESET:
            self.connection.info("Connection reset")
            doTraceback = False

        if doTraceback:
          log.exception("Exception reading connection " + str(con))
        try:
          self.connection.close()
        except:
          pass

def launch (port = 6655, address = "0.0.0.0"):

  #mirrorstatse=MirrorStates()
  #core.register("mirrorstatse", mirrorstatse)

  l = SendMesTask(port = int(port), address = address)
  core.register("SendMesTask", l)
  return l