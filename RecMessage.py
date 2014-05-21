#coding:utf-8
import socket
import time
import os
import sys
import exceptions
from struct import pack
from collections import namedtuple,defaultdict
from errno import EAGAIN, ECONNRESET, EADDRINUSE, EADDRNOTAVAIL

from connection import *
from pox.core import core
from pox.lib.recoco.recoco import *
from pox.lib.revent import *

log = core.getLogger()

import pox.openflow.libopenflow_01 as of
from pox.openflow.of_01 import unpackers
from pox.lib.pxpcap import *
from pox.lib.pxpcap.writer import *

import threading
mutex = threading.Lock()
class RecMes (Task):
  """
  The main  thread for listening to query messages
  """
  def __init__ (self, port = 6655, address = '0.0.0.0'):
    Task.__init__(self)
    self.port = int(port)
    self.address = address
    self.connection=None
    self.finallink=[]
    self.switches = set()
    self.adjacency = {}

    core.addListeners(self)
    core.openflow_discovery.addListeners(self)
    core.openflow.addListeners(self)
    #self._set_timer()


  def _handle_FlowStatsReceived(self, event):
    for reply in event.ofp:
      #print reply.show()

      flowstatsreply=mm.mms_flows_reply()
      flowstatsreply.of_convert_mms(reply,event.connection.dpid)
      if self.connection:
        self.connection.send(flowstatsreply)
  def _set_timer (self):
    self._timer = Timer(10,self.get_flows_state, recurring=False)

  def get_flows_state(self):
    '''
    for con in core.openflow._connections.itervalues():
      flowstatsrequest=of.ofp_stats_request(body=of.ofp_flow_stats_request())
      con.send(flowstatsrequest)
    '''
    try:
      for file in core.callback.dict_pxpcap.iteritems():
        for name in file:
          pass
        for PCapW in name.itervalues():
          PCapW.close()
    except:
      log.error("PCapW close error")

    for strdpid in core.callback.dict_pxpcap.iterkeys():
      for filename,PCapW in core.callback.dict_pxpcap[strdpid].iteritems():
        filereply=mm.mms_file_reply()
        (filereply.dpid,filereply.port)=filename_to_dpid(strdpid)
        filereply.filename=filename
        statinfo=os.stat(filename)
        output=open(filename,'rb')
        filereply.filedata=output.read(statinfo.st_size)
        output.close()

        input=open(filename,'ab+')
        PCapW.out=input
        PCapW.isfileopen=True
        #filereply.show()
        if self.connection:
          self.connection.send(filereply)

  def _handle_GoingUpEvent (self, event):
    self.start()

  def _handle_MirrorConnectionUp (self, event):
    print 'recMessage MirrorConnectionUp'
    hellomessage=mm.mms_hello()
    self.connection.send(hellomessage)

  def _handle_ConnectionUp (self, event):
    if self.connection:
      message=mm.mms_poxconnectionstates()
      message.dpid=event.connection.dpid
      message.connectionstates=mm.MMSCT_CONNECTION_UP
      self.connection.send(message)

  def _handle_ConnectionDown (self, event):
    if self.connection:
      message=mm.mms_poxconnectionstates()
      message.dpid=event.connection.dpid
      message.constates=mm.MMSCT_CONNECTION_DOWN
      self.connection.send(message)

  def _handle_StatesRequest (self, event):
    if event.mms.reqtypes==mm.MMSSR_TOPOLY_REQUEST:
      topolyreply=mm.mms_topoly_reply()
      #print topolyreply.show()
      topolyreply.links=self.finallink
      topolyreply.linknum=len(self.finallink)
      self.connection.send(topolyreply)

    if event.mms.reqtypes==mm.MMSSR_FLOWS_REQUEST:
      mutex.acquire()
      self.get_flows_state()
      mutex.release()


  def _handle_LinkEvent(self,event):
    if event.added==True:
      self.adjacency[event.link] = time.time()
    elif event.added==False:
      try:
        self.adjacency.pop(event.link, None)
      except:
        log.warning("Couldn't pop adjacency")
        return EventHalt

    #self.adjacency[event.link] = time.time()
    adj = defaultdict(lambda:defaultdict(lambda:[]))
    finallink=[]
    switches=set()
    # Add all links and switches
    for l in self.adjacency:
      adj[l.dpid1][l.dpid2].append(l)
      switches.add(l.dpid1)
      switches.add(l.dpid2)
    sorted(switches)
    for s1 in switches:
      for s2 in switches:
        if s2 not in adj[s1]:
          continue
        if not isinstance(adj[s1][s2], list):
          continue
        assert s1 is not s2
        good = False
        for l in adj[s1][s2]:
          if mm.flip(l) in self.adjacency:
            # This is a good one
            adj[s1][s2] = l.port1
            adj[s2][s1] = l.port2
            link=mm.Link(s1,l.port1,s2,l.port2)
            finallink.append(link)
            good = True
            break
          if not good:
            del adj[s1][s2]
            if s1 in adj[s2]:
              # Delete the other way too
              del adj[s2][s1]
    for l in finallink:
      if mm.flip(l) in finallink:
        finallink.remove(l)
    for l in finallink:
      self.switches.add(l.dpid1)
      self.switches.add(l.dpid2)
    self.finallink=finallink
    #print self.finallink
    if self.connection:
      topolyreply=mm.mms_topoly_reply()
      topolyreply.links=self.finallink
      topolyreply.linknum=len(self.finallink)
      #print topolyreply.show()
      self.connection.send(topolyreply)

  #def start (self):
    #if self.started:
      #return
    #self.started = True
    #return super(OpenFlow_01_Task,self).start()

  def run(self):
    sockets = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    log.info("Mirror application ready (to do nothing).")
    try:
      listener.bind((self.address, self.port))
    except socket.error as (errno, strerror):
      log.error("Error %i while binding socket: %s", errno, strerror)
      if errno == EADDRNOTAVAIL:
        log.error(" You may be specifying a local address which is "
                  "not assigned to any interface.")
      elif errno == EADDRINUSE:
        log.error(" Use RecMessage -port=%d to run Mirror on "% self.port)
      return
    listener.listen(5)
    sockets.append(listener)
    log.debug("Listening on %s:%s" %(self.address, self.port))

    con = None
    while core.running:
      try:
        while True:
          con = None
          rlist, wlist, elist = yield Select(sockets, [], sockets, 5)
          if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
            if not core.running: break

          for con in elist:
            if con is listener:
              raise RuntimeError("Error on RecMessage.py listener socket")
            else:
              try:
                con.close()
              except:
                pass
              try:
                sockets.remove(con)
              except:
                pass
          timestamp = time.time()
          for con in rlist:
            if con is listener:
              clientsock,clientaddr=listener.accept()
              clientsock.setblocking(0)
              self.connection=Connection(clientsock)
              sockets.append(self.connection)
              self.connection.addListeners(self)
              #test(new_con)
              #listenevents(new_con)
              #new_con.addListeners(self)
              #log.info("Client %s connected, address is%s"%clientsock.getpeername(),clientaddr)
              #print "Client", clientsock.getpeername(), " connected, address is", clientaddr
            else:
              con.idle_time = timestamp
              if con.read() is False:
                con.close()
                sockets.remove(con)
      except exceptions.KeyboardInterrupt:
        break
      except:
        doTraceback = True
        if sys.exc_info()[0] is socket.error:
          if sys.exc_info()[1][0] == ECONNRESET:
            con.info("Connection reset")
            doTraceback = False

        if doTraceback:
          log.exception("Exception reading connection " + str(con))

        if con is listener:
          log.error("Exception on Mirror listener.  Aborting.")
          break
        try:
          con.close()
        except:
          pass
        try:
          sockets.remove(con)
        except:
          pass

class PCapWriter(PCapRawWriter):
  def __init__(self,input):
    PCapRawWriter.__init__(self,input)
    self._isfileopen=True
    self.buffer = defaultdict(lambda:[])
    self.datanum=0

  @property
  def out (self):
    return self._out
  @out.setter
  def out (self, value):
    self._out=value

  @property
  def isfileopen (self):
    return self._isfileopen

  @isfileopen.setter
  def isfileopen (self, value):
    self._isfileopen=value

  def writeraw(self, buf, time = None, wire_size = None):
    if self._isfileopen==True and len(self.buffer)==0:
      self.write(buf, time = None, wire_size = None)
    elif self._isfileopen==False:
      packed = b""
      packed +=buf
      self.buffer[self.datanum].append(packed)
      self.buffer[self.datanum].append(time)
      self.buffer[self.datanum].append(wire_size)
      self.datanum+=1
    elif self._isfileopen==True and len(self.buffer)!=0:
      for data in self.buffer.itervalues():
        self.write(data[0], data[1], data[2])
      self.buffer.clear()
      self.datanum=0
    else:
      log.error("PCapWriter writeraw errror")
  def raw(self, buf, time = None, wire_size = None):
    packed = b""
    if len(buf) == 0: return
    if wire_size is None:
      wire_size = len(buf)

    assert wire_size >= len(buf), "cap size > wire size!"

    if time is None:
      t = pytime.time()
    elif isinstance(time, (datetime.datetime, datetime.time)):
      #TODO: TZ?
      t = pytime.mktime(time.timetuple()) + (time.microsecond / 1000000.0)
    else:
      t = time
    ut = t - int(t)
    t = int(t)
    ut = int(ut * 1000000)
    packed+=pack("IIII",
      t,ut,          # Timestamp
      len(buf),      # Saved size
      wire_size,     # Original size
      )

    packed+=buf
    return packed

  def close(self):
    if self._isfileopen==True and len(self.buffer)==0:
      self.out.flush()
      self.out.close()
      self._isfileopen=False
    elif self._isfileopen==True and len(self.buffer)!=0:
      for data in self.buffer.itervalues():
        self.write(data[0], data[1], data[2])
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



class Callback (object):
  def __init__(self,mininet=True):
    self.dict_pxpcap = defaultdict(lambda:defaultdict(lambda:[]))
    self.mininet=mininet
    core.openflow.addListeners(self)
    core.addListeners(self, weak=True)

  def _handle_ConnectionUp (self, event):
    (ip,port)=event.connection.sock.getpeername()
    if self.mininet==False:
      conid=dpid_to_filename(event.connection.dpid,port)
    else:
      conid=dpid_to_filename(0,port)
    file_suffix=[".flowsdat",".pakIndat",".pakOutdat"]
    file_names=['%s' % conid+name  for name in file_suffix]
    mutex.acquire()
    try:
      for name in file_names:
        input = open(name, 'wb')
        self.dict_pxpcap[conid][name]=PCapWriter(input)
    except:
      log.error("%s open error " % name)
      mutex.release()
      return
    mutex.release()

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

  def cb(self,obj, data, sec, usec, length):
    if len(self.dict_pxpcap)==0:
      return

    p_ethernet = pkt.ethernet(data)
    p_ip=p_ethernet.find(pkt.ipv4)
    p_tcp=p_ip.find(pkt.tcp)

    p_name=[]
    dst_srcport=p_ethernet.dst.toStr(separator = '')+'_'+str(p_tcp.srcport)
    dst_dstport=p_ethernet.dst.toStr(separator = '')+'_'+str(p_tcp.dstport)
    src_srcport=p_ethernet.src.toStr(separator = '')+'_'+str(p_tcp.srcport)
    src_dstport=p_ethernet.src.toStr(separator = '')+'_'+str(p_tcp.dstport)
    p_name=[dst_srcport,dst_dstport,src_srcport,src_dstport]
    find_name=None
    for name in p_name:
      if name in self.dict_pxpcap:
        find_name=name
        break
    if find_name==None:
      return
    
    PcapW_flows=None
    pcapW_pakIndat=None
    pcapW_pakOutdat=None
    for name in self.dict_pxpcap[find_name].keys():
      if name.find(".flowsdat") >0:
        PcapW_flows=self.dict_pxpcap[find_name][name]
      elif name.find(".pakIndat") >0:
        pcapW_pakIndat=self.dict_pxpcap[find_name][name]
      elif name.find(".pakOutdat") >0:
        pcapW_pakOutdat=self.dict_pxpcap[find_name][name]
      else:
        log.error("can not find openfile")
        return
    buf=p_tcp.next
    buf_len = len(p_tcp.next)
    offset = 0
    while buf_len - offset > 16: # 16 bytes is minimum MMS message size

      ofp_type = ord(buf[offset+1])

      if ord(buf[offset]) != of.OFP_VERSION:
        if ofp_type == of.OFPT_HELLO:
          pass
        else:
          log.warning("Bad MMS version (0x%02x) on connection %s"
                      % (ord(buf[offset]), self))
          return False # Throw connection away

      msg_length = ord(buf[offset+2]) << 8 | ord(buf[offset+3])

      if buf_len - offset < msg_length: break

      new_offset,msg = unpackers[ofp_type](buf, offset)
      assert new_offset - offset == msg_length
      offset = new_offset
      if ofp_type == of.OFPT_PACKET_IN:
        packetdata = pkt.ethernet(msg.data)
        lldph = packetdata.find(pkt.lldp)
        arp = packetdata.find(pkt.arp)
        icmp = packetdata.find(pkt.icmp)
        icmpv6=packetdata.find(pkt.icmpv6)
        if not lldph and not arp and not icmp and not icmpv6:
          #print msg.show()
          mutex.acquire()
          pcapW_pakIndat.writeraw(data,sec,length)
          mutex.release()
          if core.RecMes.connection:
            pcapmessage=mm.mms_pcap_message()
            pcapmessage.messagedata=pcapW_pakIndat.raw(data,sec,length)
            (pcapmessage.dpid,pcapmessage.port)=filename_to_dpid(find_name)
            pcapmessage.filename=find_name+".pakIndat"
            pcapmessage.sec=sec
            pcapmessage.messagelength=length
            core.RecMes.connection.send(pcapmessage)

      if ofp_type == of.OFPT_FLOW_MOD:
        if msg.priority!=65000:
          #print msg.show()
          mutex.acquire()
          PcapW_flows.writeraw(data,sec,length)
          mutex.release()
          if core.RecMes.connection:
            pcapmessage=mm.mms_pcap_message()
            pcapmessage.messagedata=pcapW_pakIndat.raw(data,sec,length)
            (pcapmessage.dpid,pcapmessage.port)=filename_to_dpid(find_name)
            pcapmessage.filename=find_name+".flowsdat"
            pcapmessage.sec=sec
            pcapmessage.messagelength=length
            core.RecMes.connection.send(pcapmessage)

      if ofp_type == of.OFPT_PACKET_OUT:
        if len(msg.data)!=0:
          packetdata = pkt.ethernet(msg.data)
          lldph = packetdata.find(pkt.lldp)
          arp = packetdata.find(pkt.arp)
          icmp = packetdata.find(pkt.icmp)
          icmpv6=packetdata.find(pkt.icmpv6)
          if not lldph and not arp and not icmp and not icmpv6:
            #print msg.show()
            mutex.acquire()
            pcapW_pakOutdat.writeraw(data,sec,length)
            mutex.release()
            if core.RecMes.connection:
              pcapmessage=mm.mms_pcap_message()
              pcapmessage.messagedata=pcapW_pakIndat.raw(data,sec,length)
              (pcapmessage.dpid,pcapmessage.port)=filename_to_dpid(find_name)
              pcapmessage.filename=find_name+".pakOutdat"
              pcapmessage.sec=sec
              pcapmessage.messagelength=length
              core.RecMes.connection.send(pcapmessage)


def launch (port = 6655, address = "0.0.0.0",interface='lo'):

  #print "\n".join(["%i. %s" % x for x in
                  #enumerate(PCap.get_device_names())])

  interfaces=PCap.get_device_names()
  #print interfaces

  if interface not in interfaces:
    log.info("input pcap interface error")
    raise RuntimeError("input pcap interface error")

  callback=Callback()
  core.register("callback", callback)

  of_fliter="ip proto \\tcp and tcp  port 6633  and tcp[13]  = 0x018"
  p = PCap(interface, promiscuous = False,callback = callback.cb, start=False,filter=of_fliter,period = 5)
  p.set_direction(True, True)
  p.use_select = False
  p.start()


  l = RecMes(port = int(port), address = address)
  core.register("RecMes", l)
  return l