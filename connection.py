__author__ = 'zhidoubleq'
import socket
import time
import exceptions
from errno import EAGAIN, ECONNRESET, EADDRINUSE, EADDRNOTAVAIL

from mirrorutil import *
import mesagestruct as mm
from pox.core import core
from pox.lib.revent import *

log = core.getLogger()
mms_unpackers = mm.make_type_to_unpacker_table()

def handle_HELLO (con, msg):
  #con.msg("HELLO wire protocol " + hex(msg.version))
  #con.send(msg)
  con.raiseEventNoErrors(MirrorConnectionUp, con, msg)

def handle_POXCONNECTIONSTATES (con, msg):
  if msg.constates==mm.MMSCT_CONNECTION_UP:
    con.raiseEventNoErrors(PoxConnectionUp,con, msg)
  elif msg.constates==mm.MMSCT_CONNECTION_DOWN:
    con.raiseEventNoErrors(PoxConnectionDown,con, msg)

def handle_STATES_REQUEST (con, msg):
  con.raiseEventNoErrors(StatesRequest, con, msg)

def handle_TOPOLY_REPLY (con, msg):
  con.raiseEventNoErrors(TopolyReply, con, msg)

def handle_FLOWS_REPLY (con, msg):
  con.raiseEventNoErrors(FlowsReply, con, msg)

def handle_FILE_REPLY (con, msg):
  con.raiseEventNoErrors(FileReply, con, msg)

def handle_PCAP_MESSAGE (con, msg):
  con.raiseEventNoErrors(PcapMessage, con, msg)

mms_handlers = []
# Message handlers
mms_handlerMap = {
  mm.MMS_HELLO:                 handle_HELLO,
  mm.MMS_POXCONNECTIONSTATES:   handle_POXCONNECTIONSTATES,
  mm.MMS_STATES_REQUEST:        handle_STATES_REQUEST,
  mm.MMS_TOPOLY_REPLY:          handle_TOPOLY_REPLY,
  mm.MMS_FLOWS_REPLY:           handle_FLOWS_REPLY,
  mm.MMS_FILE_REPLY:            handle_FILE_REPLY,
  mm.MMS_PCAP_MESSAGE:          handle_PCAP_MESSAGE,
}

def _set_handlers ():
  mms_handlers.extend([None] * (1 + sorted(mms_handlerMap.keys(),reverse=True)[0]))
  for h in mms_handlerMap:
    mms_handlers[h] = mms_handlerMap[h]
    #print handlerMap[h]
_set_handlers()

class PoxConnectionUp (Event):
  """
  Event raised when the connection to an OpenFlow switch has been
  established.
  """
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms

class PoxConnectionDown (Event):
  """
  Event raised when the connection to an OpenFlow switch has been
  lost.
  """
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms


class MirrorConnectionUp (Event):
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms

class StatesRequest (Event):
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms


class TopolyReply (Event):
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms

class FlowsReply (Event):
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms

class FileReply (Event):
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms

class PcapMessage (Event):
  def __init__ (self, connection, mms):
    Event.__init__(self)
    self.connection = connection
    self.mms = mms

class MirrorConnectionDown (Event):
  def __init__ (self, connection):
    Event.__init__(self)
    self.connection = connection


class Connection (EventMixin):
  _eventMixin_events = set([
    MirrorConnectionUp,
    MirrorConnectionDown,
    PoxConnectionUp,
    PoxConnectionDown,
    StatesRequest,
    TopolyReply,
    FlowsReply,
    FileReply,
    PcapMessage,
  ])

  # Globally unique identifier for the Connection instance
  ID = 0

  def msg (self, m):
    #print str(self), m
    log.debug(str(self) + " " + str(m))
  def err (self, m):
    #print str(self), m
    log.error(str(self) + " " + str(m))
  def info (self, m):
    pass
    #print str(self), m
    log.info(str(self) + " " + str(m))

  def __init__ (self, sock):
    self.sock = sock
    self.buf = ''
    Connection.ID += 1
    self.ID = Connection.ID
    self.disconnected = False
    self.disconnection_raised = False
    self.connect_time = None
    self.idle_time = time.time()

    #self.send(mm.mms_hello())
    #self.addListeners(self)
    #core.addListeners(self)
    #self._set_timer()

  def fileno (self):
    return self.sock.fileno()

  def close (self):
    self.disconnect('closed')
    try:
      self.sock.close()
    except:
      pass

  def disconnect (self, msg = 'disconnected'):
    """
    disconnect this Connection (usually not invoked manually).
    """
    if self.disconnected:
      self.msg("already disconnected")
    self.info(msg)
    self.disconnected = True
    self.raiseEventNoErrors(MirrorConnectionDown, self)

    try:
      self.sock.shutdown(socket.SHUT_RDWR)
    except:
      pass

  def send (self, data):
    """
    Send data to the switch.
    """
    if self.disconnected: return
    if type(data) is not bytes:
      # There's actually no reason the data has to be an instance of
      # ofp_header, but this check is likely to catch a lot of bugs,
      # so we check it anyway.
      #assert isinstance(data, of.ofp_header)
      data = data.pack()

    try:
      l = self.sock.send(data)
      if l != len(data):
        self.msg("Didn't send complete buffer.")
    except socket.error as (errno, strerror):
      if errno == EAGAIN:
        self.msg("Out of send buffer space.  " +
                 "Consider increasing SO_SNDBUF.")
      else:
        self.msg("Socket error: " + strerror)
        self.disconnect()


  def read (self):
    """
    Read data from this connection.
    Note: This function will block if data is not available.
    """
    try:
      d = self.sock.recv(4096)
    except:
      return False
    if len(d) == 0:
      return False
    self.buf += d
    buf_len = len(self.buf)

    offset = 0
    while buf_len - offset >= 16: # 16 bytes is minimum MMS message size

      mms_type = ord(self.buf[offset+1])
      msg_length = ord(self.buf[offset+2]) << 8 | ord(self.buf[offset+3])
      if buf_len - offset < msg_length: break

      new_offset,msg = mms_unpackers[mms_type](self.buf, offset)
      assert new_offset - offset == msg_length
      offset = new_offset

      try:
        h = mms_handlers[mms_type]
        h(self, msg)
      except:
        log.exception("%s: Exception while handling Mirror message:\n" +
                      "%s %s", self,self,
                      ("\n" + str(self) + " ").join(str(msg).split('\n')))
        continue

    if offset != 0:
      self.buf = self.buf[offset:]

    return True
#  def _set_timer (self):
#    self._timer = Timer(5,self._timer_handler, recurring=True)

#  def _timer_handler (self):
#    print 'send hello'
#    hellomessage=mm.mms_hello()
#    self.send(hellomessage)


