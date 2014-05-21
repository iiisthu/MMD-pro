#coding:utf-8

import re
import time
import exceptions
from mininet.cli import CLI
from mininet.log import setLogLevel, info,error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.node import RemoteController, OVSKernelSwitch,Controller


from pox.core import core
from pox.lib.recoco.recoco import *
from pox.lib.revent.revent import EventMixin
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str, str_to_bool

log = core.getLogger()

import threading
from collections import namedtuple,defaultdict
mutex = threading.Lock()

class mininettask (object):

  def __init__(self, connection):
    self.connection = connection
    self.finallink=[]
    self.switches = set()
    self.adjacency = {}

    connection.addListeners(self)
    core.openflow_discovery.addListenerByName("LinkEvent", self._handle_LinkEvent)

  def flip (self,link):
    return Link(link[2],link[3], link[0],link[1])

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
          if self.flip(l) in self.adjacency:
            # This is a good one
            adj[s1][s2] = l.port1
            adj[s2][s1] = l.port2
            link=Link(s1,l.port1,s2,l.port2)
            finallink.append(link)
            good = True
            break
          if not good:
            del adj[s1][s2]
            if s1 in adj[s2]:
              # Delete the other way too
              del adj[s2][s1]
    for l in finallink:
      if self.flip(l) in finallink:
        finallink.remove(l)
    for l in finallink:
      self.switches.add(l.dpid1)
      self.switches.add(l.dpid2)
    self.finallink=finallink
    #print self.finallink

  def gettoptly(self):
    mutex.acquire()
    print 'gettopoly'

    if len(self.addlinks)<len(self.finallink):#add Link
      print 'breakdsafasdf'
      for s in self.switches:
        #print s
        if self.addswitches.get(s)==None:
          #print dpid_to_str(s)
          self.snum+=1
          switch = self.net.addSwitch('s%s'%self.snum)
          if s==1:
            for h in range(3):
              host = self.net.addHost('h%s' % (h + 4))
              self.net.addLink(host, switch)
            self.net.configHosts()
          print self.net.controllers,switch
          switch.start(self.net.controllers)
          self.addswitches[s]=switch


      for l in self.finallink:
        if not self.addlinks.count(l) or not self.addlinks.count(self.flip(l)):
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
      self.receivelinkevent=0;
      mutex.release()
      return
    if len(self.addlinks)>len(self.finallink):#delete Link
      print self.addlinks
      print self.finallink
      print self.statuslinks
      for l in self.addlinks:
        if not self.finallink.count(l) or not self.finallink.count(self.flip(l)):
          if self.statuslinks.has_key(l):
            self.statuslinks[l].delete()
            self.statuslinks.pop(l, None)
            self.addlinks.remove(l)
          elif self.statuslinks.has_key(self.flip(l)):
            linkflip=self.flip(l)
            self.statuslinks[linkflip].delete()
            self.statuslinks.pop(linkflip, None)
            self.addlinks.remove(linkflip)
          #con = core.openflow.getConnection(dpid)
  #if con is None: return

    self.receivelinkevent=0;
    mutex.release()

  def run(self):
    print self.receivelinkevent

    setLogLevel("info")
    OVSKernelSwitch.setup()#"Make sure Open vSwitch is installed and working"

    info("****creating network****\n")
    self.net = Mininet(listenPort = self.listenPort)

    controller = RemoteController("mirrorController",   ip = "127.0.0.1")
    self.net.addController(controller)
    #self.gettoptly()
    timesnum=0;
    while core.running:
      try:
        while True:
          rlist, wlist, elist = yield Select([self.receivelinkevent], [], [], 5)
          if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
            #self.gettoptly()
            if not core.running: break
          #if len(rlist)!=0:
            #print self.receivelinkevent
          if self.receivelinkevent==1:
            self.gettoptly()
            timesnum+=1
            if timesnum==5:
              self.net.pingAll()
      except exceptions.KeyboardInterrupt:
        break
    self.net.stop()
def launch (Port = 6633, address = "0.0.0.0"):

  print"mininet begin"
  l = mininettask(listenPort = int(Port), address = address)
  core.register("mininettask", l)
  return l__author__ = 'zhidoubleq'
