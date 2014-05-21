__author__ = 'zhidoubleq'
import binascii
import struct

from mirrorutil import *
from pox.lib.addresses import *

EMPTY_ETH = EthAddr(None)
# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

_logger = None
def _log (debug=None, info=None, warn=None, error=None):
  if not _logger: return
  if debug: _logger.debug(debug)
  if info: _logger.info(info)
  if warn: _logger.warn(warn)
  if error: _logger.error(error)
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# XID Management
# ----------------------------------------------------------------------

MAX_XID = 0x7fFFffFF


def XIDGenerator (start = 1, stop = MAX_XID):
  i = start
  while True:
    yield i
    i += 1
    if i > stop:
      i = start

def xid_generator (start = 1, stop = MAX_XID):
  return XIDGenerator(start, stop).next

def user_xid_generator ():
  return xid_generator(0x80000000, 0xffFFffFF)

generate_xid = xid_generator()

# ----------------------------------------------------------------------
# Packing / Unpacking
# ----------------------------------------------------------------------

_PAD = b'\x00'
_PAD2 = _PAD*2
_PAD3 = _PAD*3
_PAD4 = _PAD*4
_PAD6 = _PAD*6


mms_port_rev_map = {
  'OFPP_MAX'        : 65280,
  'OFPP_IN_PORT'    : 65528,
  'OFPP_TABLE'      : 65529,
  'OFPP_NORMAL'     : 65530,
  'OFPP_FLOOD'      : 65531,
  'OFPP_ALL'        : 65532,
  'OFPP_CONTROLLER' : 65533,
  'OFPP_LOCAL'      : 65534,
  'OFPP_NONE'       : 65535,
}
mms_flow_wildcards_rev_map = {
  'OFPFW_IN_PORT'      : 1,
  'OFPFW_DL_VLAN'      : 2,
  'OFPFW_DL_SRC'       : 4,
  'OFPFW_DL_DST'       : 8,
  'OFPFW_DL_TYPE'      : 16,
  'OFPFW_NW_PROTO'     : 32,
  'OFPFW_TP_SRC'       : 64,
  'OFPFW_TP_DST'       : 128,
  'OFPFW_DL_VLAN_PCP'  : 1048576,
  'OFPFW_NW_TOS'       : 1<<21,
}
mms_flow_mod_command_rev_map = {
  'OFPFC_ADD'           : 0,
  'OFPFC_MODIFY'        : 1,
  'OFPFC_MODIFY_STRICT' : 2,
  'OFPFC_DELETE'        : 3,
  'OFPFC_DELETE_STRICT' : 4,
}
OFPFW_NW_DST_BITS      = 6
OFPFW_NW_SRC_BITS      = 6
OFPFW_NW_SRC_SHIFT     = 8
OFPFW_NW_DST_SHIFT     = 14
OFPFW_NW_SRC_ALL       = 8192
OFPFW_NW_SRC_MASK      = 16128
OFPFW_NW_DST_ALL       = 524288
OFPFW_NW_DST_MASK      = 1032192
# Note: Need to handle all flags that are set in this.
# glob-all masks in the packet handling methods.
# (Esp. ofp_match.from_packet)
# Otherwise, packets are not being matched as they should
OFPFW_ALL              = ((1 << 22) - 1)
NO_BUFFER = 4294967295

MMS_VERSION= 0x01
MMSSR_TOPOLY_REQUEST=0x01
MMSSR_FLOWS_REQUEST=0x02



MMSCT_CONNECTION_UP=0x00
MMSCT_CONNECTION_DOWN=0x01


def _read (data, offset, length):
  if (len(data)-offset) < length:
    raise RuntimeError("wanted %s bytes but only have %s"
                        % (length, len(data)-offset))
  return (offset+length, data[offset:offset+length])

def _unpack (fmt, data, offset):
  size = struct.calcsize(fmt)
  if (len(data)-offset) < size: raise RuntimeError()
  return (offset+size, struct.unpack_from(fmt, data, offset))

def _skip (data, offset, num):
  offset += num
  if offset > len(data): raise UnderrunError()
  return offset

def _readether (data, offset):
  (offset, d) = _read(data, offset, 6)
  return (offset, EthAddr(d))

def _readip (data, offset, networkOrder = True):
  (offset, d) = _read(data, offset, 4)
  return (offset, IPAddr(d, networkOrder = networkOrder))

def _unpack_actions (b, length, offset=0):
  """
  Parses actions from a buffer
  b is a buffer (bytes)
  offset, if specified, is where in b to start decoding
  returns (next_offset, [Actions])
  """
  if (len(b) - offset) < length: raise UnderrunError
  actions = []
  end = length + offset
  while offset < end:
    (t,l) = struct.unpack_from("!HH", b, offset)
    if (len(b) - offset) < l: raise UnderrunError
    a = _action_type_to_class.get(t)
    if a is None:
      # Use generic action header for unknown type
      a = ofp_action_generic()
    else:
      a = a()
    a.unpack(b[offset:offset+l])
    assert len(a) == l
    actions.append(a)
    offset += l
  return (offset, actions)

def hexdump (data):
  """
  Converts raw data to a hex dump
  """
  if isinstance(data, (str,bytes)):
    data = [ord(c) for c in data]
  o = ""
  def chunks (data, length):
    return (data[i:i+length] for i in xrange(0, len(data), length))
  def filt (c):
    if c >= 32 and c <= 126: return chr(c)
    return '.'

  for i,chunk in enumerate(chunks(data,16)):
    if i > 0: o += "\n"
    o += "%04x: " % (i * 16,)
    l = ' '.join("%02x" % (c,) for  c in chunk)
    l = "%-48s" % (l,)
    l = l[:3*8-1] + "  " + l[3*8:]
    t = ''.join([filt(x) for x in chunk])
    l += '  |%-16s|' % (t,)
    o += l
  return o


def _format_body (body, prefix):
  if hasattr(body, 'show'):
    #TODO: Check this (spacing may well be wrong)
    return body.show(prefix + '  ')
  else:
    return prefix + hexdump(body).replace("\n", "\n" + prefix)

mms_type_rev_map = {}
mms_type_map = {}
_message_type_to_class = {}
def mirror_message (mms_type, type_val):
  mms_type_rev_map[mms_type] = type_val
  mms_type_map[type_val] = mms_type
  def f (c):
    c.header_type = type_val
    _message_type_to_class[type_val] = c
    return c
  return f

class _StatsClassInfo (object):
  __slots__ = 'request reply reply_is_list'.split()

  def __init__ (self, **kw):
    self.request = None
    self.reply = None
    self.reply_is_list = False
    initHelper(self, kw)

  def __str__ (self):
    r = str(self.reply)
    if self.reply_is_list: r = "[%s]" % (r,)
    return "request:%s reply:%s" % (self.request, r)

_stats_type_to_class_info = {}
_stats_class_to_type = {}
mms_stats_type_rev_map = {}
mms_stats_type_map = {}

def mirror_stats_reply  (stats_type, type_val=None, is_list=None,
    is_reply = False):
  if type_val is not None:
    mms_stats_type_rev_map[stats_type] = type_val
    mms_stats_type_map[type_val] = stats_type
  else:
    type_val = mms_stats_type_rev_map.get(stats_type)

  def f (c):
    if type_val is not None:
      ti = _stats_type_to_class_info.get(stats_type)
      if ti is not None:
        _stats_type_to_class_info[type_val] = ti
        del _stats_type_to_class_info[stats_type]
      else:
        ti = _stats_type_to_class_info.setdefault(type_val,
            _StatsClassInfo())
      _stats_class_to_type[c] = type_val
    else:
      ti = _stats_type_to_class_info.setdefault(stats_type,
          _StatsClassInfo())

    if is_list is not None:
      ti.reply_is_list = is_list
    if is_reply:
      ti.reply = c
    else:
      ti.request = c

    if type_val is not None:
      yes = False
      if ti.reply is not None and issubclass(ti.reply,mms_stats_body_base):
        ti.reply._type = type_val
        yes = True
      if ti.request is not None and issubclass(ti.request,mms_stats_body_base):
        ti.request._type = type_val
        yes = True
      assert yes, "Type not set for " + str(stats_type)

    return c
  return f

_action_type_to_class = {}
_action_class_to_types = {} # Do we need this?
mms_action_type_rev_map = {}
mms_action_type_map = {}

def mirror_action (action_type, type_val):
  mms_action_type_rev_map[action_type] = type_val
  mms_action_type_map[type_val] = action_type
  def f (c):
    c.type = type_val
    _action_type_to_class[type_val] = c
    _action_class_to_types.setdefault(c, set()).add(type_val)
    return c
  return f

class _mms_meta (type):
  """
  Metaclass for mirror messages/structures
  This takes care of making len() work as desired.
  """
  def __len__ (cls):
    try:
      return cls.__len__()
    except:
      return cls._MIN_LENGTH

class mms_base (object):

  __metaclass__ = _mms_meta

  def _assert (self):
    r = self._validate()
    if r is not None:
      raise RuntimeError(r)
      return False # Never reached
    return True

  def _validate (self):
    return None

  def __ne__ (self, other):
    return not self.__eq__(other)

  @classmethod
  def unpack_new (cls, raw, offset=0):
    """
    Unpacks wire format into the appropriate message object.
    Returns newoffset,object
    """
    o = cls()
    r,length = o.unpack(raw, offset)
    assert (r-offset) == length, o
    return (r, o)

class mms_header (mms_base):
  _MIN_LENGTH = 16
  def __init__ (self, **kw):
    self.version = MMS_VERSION
    self._xid = None
    self.dpid = 0
    if 'header_type' in kw:
      self.header_type = kw.pop('header_type')

    initHelper(self, kw)

  @property
  def xid (self):
    if self._xid is None:
      self._xid = generate_xid()
    return self._xid

  @xid.setter
  def xid (self, val):
    self._xid = val

  def _validate (self):
    if self.header_type not in mms_type_map:
      return "type is not a known message type"
    return None

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!BBHLQ", self.version, self.header_type,len(self), self.xid, self.dpid)
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    return offset,length

  def _unpack_header (self, raw, offset):
    offset,(self.version, self.header_type, length, self.xid, self.dpid) = _unpack("!BBHLQ", raw, offset)
    return offset,length


  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.version != other.version: return False
    if self.header_type != other.header_type: return False
    if len(self) != len(other): return False
    if self.xid != other.xid: return False
    if self.dpid != other.dpid: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'version: ' + str(self.version) + '\n'
    outstr += prefix + 'type:    ' + str(self.header_type)# + '\n'
    outstr += " (" + mms_type_map.get(self.header_type, "Unknown") + ")\n"
    try:
      outstr += prefix + 'length:  ' + str(len(self)) + '\n'
    except:
      pass
    outstr += prefix + 'xid:     ' + str(self.xid) + '\n'
    outstr += prefix + 'dpid:    ' + dpid_to_str(self.dpid) + '\n'
    return outstr

  def __str__ (self):
    return self.__class__.__name__ + "\n  " + self.show('  ').strip()

class mms_stats_body_base (mms_base):
  """
  Base class for stats bodies
  """
  _type = None

  """
  def unpack (self, data, offset=0, avail=None):
  """

class mms_action_base (mms_base):
  """
  Base class for actions

  This is sort of the equivalent of ofp_action_header in the spec.
  However, ofp_action_header as the spec defines it is not super
  useful for us, as it has the padding in it.
  """
  type = None

  @classmethod
  def unpack_new (cls, raw, offset=0):
    """
    Unpacks wire format into the appropriate action object.

    Returns newoffset,object
    """
    o = cls()
    r = o.unpack(raw, offset)
    assert (r-offset) == len(o), o
    return (r, o)


@mirror_message("MMS_HELLO", 0)
class mms_hello (mms_header):
  def __init__ (self, **kw):
    mms_header.__init__(self)

  def pack (self):
    packed = b""
    packed += mms_header.pack(self)
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    assert length == len(self)
    return offset,length

  @staticmethod
  def __len__ ():
    return 16

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    return outstr

@mirror_message("MMS_POXCONNECTIONSTATES", 1)
class mms_poxconnectionstates (mms_header):
  _MIN_LENGTH = 17
  def __init__ (self, **kw):
    mms_header.__init__(self)
    self.constates=0 # 0:up 1:down

  def pack (self):
    assert self._assert()
    packed = b""
    packed += mms_header.pack(self)
    packed +=struct.pack("!B", self.constates)
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset,data = _read(raw, offset, struct.calcsize("!B"))
    (self.constates,)=struct.unpack("!B",data)
    assert length == len(self)
    return offset,length

  def __len__ (self):
    return 16 + struct.calcsize("!B")

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    if self.constates != other.constates: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    outstr += prefix + 'states:'
    if self.constates==MMSCT_CONNECTION_UP:
      outstr +="Up"
    elif self.constates==MMSCT_CONNECTION_DOWN:
      outstr +="Down"
    return outstr

@mirror_message("MMS_STATES_REQUEST", 2)
class mms_states_request (mms_header):
  _MIN_LENGTH = 17
  def __init__ (self, **kw):
    mms_header.__init__(self)
    self.reqtypes = 0

  def pack (self):
    assert self._assert()
    packed = b""
    packed += mms_header.pack(self)
    packed +=struct.pack("!B", self.reqtypes)
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset,data = _read(raw, offset, struct.calcsize("!B"))
    (self.reqtypes,)=struct.unpack("!B",data)
    assert length == len(self)
    return offset,length

  def __len__ (self):
    return 16 + struct.calcsize("!B")

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    if self.reqtypes != other.reqtypes: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    outstr += prefix + 'RequestTpye:'+ str(self.reqtypes) + '\n'
    #outstr += _format_body(self.body, prefix + '  ') + '\n'
    return outstr


@mirror_message("MMS_TOPOLY_REPLY", 3)
class mms_topoly_reply (mms_header):
  _MIN_LENGTH = 16
  def __init__ (self, **kw):
    mms_header.__init__(self)
    self.linknum=0
    self.links=[]


  def pack (self):
    assert self._assert()
    packed = b""
    packed += mms_header.pack(self)
    for link in self.links:
      packed +=struct.pack("!QBQB", link.dpid1, link.port1,link.dpid2,link.port2)
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    self.linknum = (length - offset)/struct.calcsize("!QBQB")
    for link in xrange(0, self.linknum):
      offset,data = _read(raw, offset, struct.calcsize("!QBQB"))
      (dpid1,port1,dpid2,port2)=struct.unpack("!QBQB",data)
      self.links.append(Link(dpid1, port1,dpid2,port2))
    assert length == len(self)
    return offset,length

  def __len__ (self):
    return 16  + struct.calcsize("!QBQB") *len(self.links)

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    if self.links != other.links: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    outstr += prefix + 'link: \n'
    for link in self.links:
      outstr += '  ' + link.__str__() +'\n'
    return outstr


from collections import namedtuple,defaultdict
class Link (namedtuple("LinkBase",("dpid1","port1","dpid2","port2"))):
  @property
  def uni (self):
    """
    Returns a "unidirectional" version of this link

    The unidirectional versions of symmetric keys will be equal
    """
    pairs = list(self.end)
    pairs.sort()
    return Link(pairs[0][0],pairs[0][1],pairs[1][0],pairs[1][1])

  @property
  def end (self):
    return ((self[0],self[1]),(self[2],self[3]))

  def __str__ (self):
    return "%s.%s -> %s.%s" % (dpid_to_str(self[0]),self[1],
                               dpid_to_str(self[2]),self[3])

  def __repr__ (self):
    return "Link(dpid1=%s,port1=%s, dpid2=%s,port2=%s)" % (self.dpid1,
        self.port1, self.dpid2, self.port2)

def flip (link):
    return Link(link[2],link[3], link[0],link[1])

class mms_match (mms_base):
  adjust_wildcards = True # Set to true to "fix" outgoing wildcards

  @classmethod
  def from_packet (cls, packet, in_port = None, spec_frags = False):
    """
    Constructs an exact match for the given packet

    @param in_port The switch port the packet arrived on if you want
                   the resulting match to have its in_port set.
                   If "packet" is a packet_in, this is ignored.
    @param packet  A pox.packet.ethernet instance or a packet_in
    @param spec_frags Handle IP fragments as specified in the spec.
    """
    if isinstance(packet, ofp_packet_in):
      in_port = packet.in_port
      packet = ethernet(packet.data)
    assert assert_type("packet", packet, ethernet, none_ok=False)

    match = cls()

    if in_port is not None:
      match.in_port = in_port

    match.dl_src = packet.src
    match.dl_dst = packet.dst
    match.dl_type = packet.type
    p = packet.next

    # Is this in the spec?
    if packet.type < 1536:
      match.dl_type = OFP_DL_TYPE_NOT_ETH_TYPE
    # LLC then VLAN?  VLAN then LLC?
    if isinstance(p, llc):
      if p.has_snap and p.oui == '\0\0\0':
        match.dl_type = p.eth_type
        p = p.next
    if isinstance(p, vlan):
      match.dl_type = p.eth_type
      match.dl_vlan = p.id
      match.dl_vlan_pcp = p.pcp
      p = p.next
    else:
      match.dl_vlan = OFP_VLAN_NONE
      match.dl_vlan_pcp = 0

    if isinstance(p, ipv4):
      match.nw_src = p.srcip
      match.nw_dst = p.dstip
      match.nw_proto = p.protocol
      match.nw_tos = p.tos
      if spec_frags and ((p.flags & p.MF_FLAG) or p.frag != 0):
        # This seems a bit strange, but see page 9 of the spec.
        match.tp_src = 0
        match.tp_dst = 0
        return match
      p = p.next

      if isinstance(p, udp) or isinstance(p, tcp):
        match.tp_src = p.srcport
        match.tp_dst = p.dstport
      elif isinstance(p, icmp):
        match.tp_src = p.type
        match.tp_dst = p.code
    elif isinstance(p, arp):
      if p.opcode <= 255:
        match.nw_proto = p.opcode
        match.nw_src = p.protosrc
        match.nw_dst = p.protodst

    return match

  def clone (self):
    n = mms_match()
    for k,v in mms_match_data.iteritems():
      setattr(n, '_' + k, getattr(self, '_' + k))
    n.wildcards = self.wildcards
    return n

  def flip (self, in_port = True):
    """
    Return version of this match with src and dst fields swapped

    in_port can be:
      True  : Include same in_port in new match
      Other : Set Other as in_port in new match
    """
    reversed = self.clone()
    for field in ('dl','nw','tp'):
      setattr(reversed, field + '_src', getattr(self, field + '_dst'))
      setattr(reversed, field + '_dst', getattr(self, field + '_src'))
    if in_port is not True:
      reversed.in_port = in_port

    return reversed

  def __init__ (self, **kw):
    self._locked = False

    for k,v in mms_match_data.iteritems():
      setattr(self, '_' + k, v[0])

    self.wildcards = self._normalize_wildcards(OFPFW_ALL)

    # This is basically initHelper(), but tweaked slightly since this
    # class does some magic of its own.
    for k,v in kw.iteritems():
      if not hasattr(self, '_'+k):
        raise TypeError(self.__class__.__name__ + " constructor got "
          + "unexpected keyword argument '" + k + "'")
      setattr(self, k, v)

  def get_nw_dst (self):
    if (self.wildcards & OFPFW_NW_DST_ALL) == OFPFW_NW_DST_ALL:
      return (None, 0)

    w = (self.wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
    return (self._nw_dst,32-w if w <= 32 else 0)

  def get_nw_src (self):
    if (self.wildcards & OFPFW_NW_SRC_ALL) == OFPFW_NW_SRC_ALL:
      return (None, 0)

    w = (self.wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
    return (self._nw_src,32-w if w <= 32 else 0)

  def set_nw_dst (self, *args, **kw):
    a = self._make_addr(*args, **kw)
    if a is None:
      self._nw_dst = mms_match_data['nw_dst'][0]
      self.wildcards &= ~OFPFW_NW_DST_MASK
      self.wildcards |= mms_match_data['nw_dst'][1]
      return
    self._nw_dst = a[0]
    self.wildcards &= ~OFPFW_NW_DST_MASK
    self.wildcards |= ((32-a[1]) << OFPFW_NW_DST_SHIFT)

  def set_nw_src (self, *args, **kw):
    a = self._make_addr(*args, **kw)
    if a is None:
      self._nw_src = mms_match_data['nw_src'][0]
      self.wildcards &= ~OFPFW_NW_SRC_MASK
      self.wildcards |= mms_match_data['nw_src'][1]
      return
    self._nw_src = a[0]
    self.wildcards &= ~OFPFW_NW_SRC_MASK
    self.wildcards |= ((32-a[1]) << OFPFW_NW_SRC_SHIFT)

  def _make_addr (self, ipOrIPAndBits, bits=None):
    if ipOrIPAndBits is None: return None
    b = None
    if type(ipOrIPAndBits) is tuple:
      ip = ipOrIPAndBits[0]
      b = int(ipOrIPAndBits[1])

    if (type(ipOrIPAndBits) is str) and (len(ipOrIPAndBits) != 4):
      if ipOrIPAndBits.find('/') != -1:
        #s = ipOrIPAndBits.split('/')
        s = parse_cidr(ipOrIPAndBits, infer=False)
        ip = s[0]
        b = int(s[1]) if b is None else b
      else:
        ip = ipOrIPAndBits
        b = 32 if b is None else b
    else:
      ip = ipOrIPAndBits
      b = 32 if b is None else b

    if type(ip) is str:
      ip = IPAddr(ip)

    if bits != None: b = bits
    if b > 32: b = 32
    elif b < 0: b = 0

    return (ip, b)

  def __setattr__ (self, name, value):
    if name == '_locked':
      super(mms_match,self).__setattr__(name, value)
      return

    if self._locked:
      raise AttributeError('match object is locked')

    if name not in mms_match_data:
      self.__dict__[name] = value
      return

    if name == 'nw_dst' or name == 'nw_src':
      # Special handling
      getattr(self, 'set_' + name)(value)
      return value

    if value is None:
      setattr(self, '_' + name, mms_match_data[name][0])
      self.wildcards |= mms_match_data[name][1]
    else:
      setattr(self, '_' + name, value)
      self.wildcards = self.wildcards & ~mms_match_data[name][1]

    return value

  def __getattr__ (self, name):
    if name in mms_match_data:
      if ( (self.wildcards & mms_match_data[name][1])
           == mms_match_data[name][1] ):
        # It's wildcarded -- always return None
        return None
      if name == 'nw_dst' or name == 'nw_src':
        # Special handling
        return getattr(self, 'get_' + name)()[0]
      return self.__dict__['_' + name]
    raise AttributeError("attribute not found: "+name)

  def _validate (self):
    # TODO
    return None

  def _prereq_warning (self):
    # Only checked when assertions are on
    if not _logger: return True
    om = self.clone()
    om.fix()

    if om == self: return True

    msg = "Fields ignored due to unspecified prerequisites: "
    wcs = []

    for name in mms_match_data.keys():
      if getattr(self,name) is None: continue
      if getattr(om,name) is not None: continue
      wcs.append(name)

    msg = msg + " ".join(wcs)

    _log(warn = msg)
    _log(debug = "Problematic match: " + str(self))

    return True # Always; we don't actually want an assertion error

  def pack (self, flow_mod=False):
    assert self._assert()

    packed = b""
    if self.adjust_wildcards and flow_mod:
      wc = self._wire_wildcards(self.wildcards)
      assert self._prereq_warning()
    else:
      wc = self.wildcards
    packed += struct.pack("!LH", wc, self.in_port or 0)
    if self.dl_src is None:
      packed += EMPTY_ETH.toRaw()
    elif type(self.dl_src) is bytes:
      packed += self.dl_src
    else:
      packed += self.dl_src.toRaw()
    if self.dl_dst is None:
      packed += EMPTY_ETH.toRaw()
    elif type(self.dl_dst) is bytes:
      packed += self.dl_dst
    else:
      packed += self.dl_dst.toRaw()

    def check_ip(val):
      return (val or 0) if self.dl_type == 0x0800 else 0
    def check_ip_or_arp(val):
      return (val or 0) if self.dl_type == 0x0800 \
                           or self.dl_type == 0x0806 else 0
    def check_tp(val):
      return (val or 0) if self.dl_type == 0x0800 \
                           and self.nw_proto in (1,6,17) else 0

    packed += struct.pack("!HB", self.dl_vlan or 0, self.dl_vlan_pcp or 0)
    packed += _PAD # Hardcode padding
    packed += struct.pack("!HBB", self.dl_type or 0,
        check_ip(self.nw_tos), check_ip_or_arp(self.nw_proto))
    packed += _PAD2 # Hardcode padding
    def fix (addr):
      if addr is None: return 0
      if type(addr) is int: return addr & 0xffFFffFF
      if type(addr) is long: return addr & 0xffFFffFF
      return addr.toUnsigned()

    packed += struct.pack("!LLHH", check_ip_or_arp(fix(self.nw_src)),
        check_ip_or_arp(fix(self.nw_dst)),
        check_tp(self.tp_src), check_tp(self.tp_dst))

    return packed

  def _normalize_wildcards (self, wildcards):
    """
    nw_src and nw_dst values greater than 32 mean the same thing as 32.
    We normalize them here just to be clean and so that comparisons act
    as you'd want them to.
    """
    if ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT) > 32:
      wildcards &= ~OFPFW_NW_SRC_MASK
      wildcards |= (32 << OFPFW_NW_SRC_SHIFT)
    if ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT) > 32:
      wildcards &= ~OFPFW_NW_DST_MASK
      wildcards |= (32 << OFPFW_NW_DST_SHIFT)
    return wildcards

  def _wire_wildcards (self, wildcards):
    """
    Normalize the wildcard bits

    Note the following from the OpenFlow 1.1 spec:

      Protocol-specific fields within ofp_match will be ignored within
      a single table when the corresponding protocol is not specified in the
      match.  The IP header and transport header fields
      will be ignored unless the Ethertype is specified as either IPv4 or
      ARP. The tp_src and tp_dst fields will be ignored unless the network
      protocol specified is as TCP, UDP or SCTP. Fields that are ignored
      don't need to be wildcarded and should be set to 0.

    OpenFlow 1.0.1 Section 3.4 actually has an improved version of the above,
    but we won't quote it here because it seems to have a restrictive license.
    """
    #TODO: Set the masked fields to 0.
    if self.dl_type == 0x0800:
        # IP
        if  self.nw_proto not in (1,6,17):
          # not TCP/UDP/ICMP -> Clear TP wildcards for the wire
          return wildcards & ~(OFPFW_TP_SRC | OFPFW_TP_DST)
        else:
          return wildcards
    elif self.dl_type == 0x0806:
        # ARP: clear NW_TOS / TP wildcards for the wire
        return wildcards & ~( OFPFW_NW_TOS | OFPFW_TP_SRC | OFPFW_TP_DST)
    else:
        # not even IP. Clear NW/TP wildcards for the wire
        return wildcards & ~( OFPFW_NW_TOS | OFPFW_NW_PROTO
            | OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK
            | OFPFW_TP_SRC | OFPFW_TP_DST)

  def fix (self):
    """
    Removes unmatchable fields

    The logic in this should exactly match that in _wire_wildcards()
    """
    if self.dl_type == 0x0800:
        # IP
        if  self.nw_proto not in (1,6,17):
          # not TCP/UDP/ICMP -> Clear TP wildcards for the wire
          self.tp_src = None
          self.tp_dst = None
          return
    elif self.dl_type == 0x0806:
        # ARP: clear NW_TOS / TP wildcards for the wire
        self.tp_src = None
        self.tp_dst = None
        self.nw_tos = None
        return
    else:
        # not even IP. Clear NW/TP wildcards for the wire
        self.nw_tos = None
        self.nw_proto = None
        self.nw_src = None
        self.nw_dst = None
        self.tp_src = None
        self.tp_dst = None
        return

  def _unwire_wildcards (self, wildcards):
    """
    Normalize the wildcard bits from the openflow wire representation.

    Note this atrocity from the OF1.1 spec:
    Protocol-specific fields within ofp_match will be ignored within
    a single table when the corresponding protocol is not specified in the
    match.  The IP header and transport header fields
    will be ignored unless the Ethertype is specified as either IPv4 or
    ARP. The tp_src and tp_dst fields will be ignored unless the network
    protocol specified is as TCP, UDP or SCTP. Fields that are ignored
    don't need to be wildcarded and should be set to 0.
    """
    if self._dl_type == 0x0800:
        # IP
        if  self._nw_proto not in (1,6,17):
          # not TCP/UDP/ICMP -> Set TP wildcards for the object
          return wildcards | (OFPFW_TP_SRC | OFPFW_TP_DST)
        else:
          return wildcards
    elif self._dl_type == 0x0806:
        # ARP: Set NW_TOS / TP wildcards for the object
        return wildcards | ( OFPFW_NW_TOS | OFPFW_TP_SRC | OFPFW_TP_DST)
    else:
        # not even IP. Set NW/TP wildcards for the object
        return wildcards | ( OFPFW_NW_TOS | OFPFW_NW_PROTO
                             | OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK
                             | OFPFW_TP_SRC | OFPFW_TP_DST)


  @property
  def is_wildcarded (self):
    return self.wildcards & OFPFW_ALL != 0

  @property
  def is_exact (self):
    return not self.is_wildcarded

  def unpack (self, raw, offset=0, flow_mod=False):
    _offset = offset
    offset,(wildcards, self._in_port) = _unpack("!LH",raw, offset)
    offset,self._dl_src = _readether(raw, offset)
    offset,self._dl_dst = _readether(raw, offset)
    offset,(self._dl_vlan, self._dl_vlan_pcp) = \
        _unpack("!HB", raw, offset)
    offset = _skip(raw, offset, 1)
    offset,(self._dl_type, self._nw_tos, self._nw_proto) = \
        _unpack("!HBB", raw, offset)
    offset = _skip(raw, offset, 2)
    offset,self._nw_src = _readip(raw, offset)
    offset,self._nw_dst = _readip(raw, offset)
    offset,(self._tp_src, self._tp_dst) = _unpack("!HH", raw, offset)

    # Only unwire wildcards for flow_mod
    self.wildcards = self._normalize_wildcards(
        self._unwire_wildcards(wildcards) if flow_mod else wildcards)

    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 40

  def hash_code (self):
    """
    generate a hash value for this match

    This generates a hash code which might be useful, but without locking
    the match object.
    """

    h = self.wildcards
    for f in mms_match_data:
      v = getattr(self, f)
      if type(v) is int:
        h ^= v
      elif type(v) is long:
        h ^= v
      else:
        h ^= hash(v)

    return int(h & 0x7fFFffFF)

  def __hash__ (self):
    self._locked = True
    return self.hash_code()

  def matches_with_wildcards (self, other, consider_other_wildcards=True):
    """
    Test whether /this/ match completely encompasses the other match.

    if consider_other_wildcards, then the *other* match must also have
    no more wildcards than we do (it must be no wider than we are)

    Important for non-strict modify flow_mods etc.
    """
    assert assert_type("other", other, ofp_match, none_ok=False)

    # shortcut for equal matches
    if self == other: return True

    if consider_other_wildcards:
      # Check that other doesn't have more wildcards than we do -- it
      # must be narrower (or equal) to us.
      self_bits  = self.wildcards&~(OFPFW_NW_SRC_MASK|OFPFW_NW_DST_MASK)
      other_bits = other.wildcards&~(OFPFW_NW_SRC_MASK|OFPFW_NW_DST_MASK)
      if (self_bits | other_bits) != self_bits: return False

    def match_fail (mine, others):
      if mine is None: return False # Wildcarded
      return mine != others

    if match_fail(self.in_port, other.in_port): return False
    if match_fail(self.dl_vlan, other.dl_vlan): return False
    if match_fail(self.dl_src, other.dl_src): return False
    if match_fail(self.dl_dst, other.dl_dst): return False
    if match_fail(self.dl_type, other.dl_type): return False
    if match_fail(self.nw_proto, other.nw_proto): return False
    if match_fail(self.tp_src, other.tp_src): return False
    if match_fail(self.tp_dst, other.tp_dst): return False
    if match_fail(self.dl_vlan_pcp, other.dl_vlan_pcp): return False
    if match_fail(self.nw_tos, other.nw_tos): return False

    #FIXME: The two ??? checks below look like they compare other
    #       wildcards always -- even when consider_other_wildcards=False.
    #       Is this intentional?  (I think it might be subtly wrong and
    #       we actually may need to mask off some bits and do the
    #       inNetwork check or something...)

    self_nw_src = self.get_nw_src()
    if self_nw_src[0] is not None:
      other_nw_src = other.get_nw_src()
      if self_nw_src[1] > other_nw_src[1]: return False #???
      if not IPAddr(other_nw_src[0]).inNetwork(
            (self_nw_src[0], self_nw_src[1])): return False

    self_nw_dst = self.get_nw_dst()
    if self_nw_dst[0] is not None:
      other_nw_dst = other.get_nw_dst()
      if self_nw_dst[1] > other_nw_dst[1]: return False #???
      if not IPAddr(other_nw_dst[0]).inNetwork(
            (self_nw_dst[0], self_nw_dst[1])): return False

    return True

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.wildcards != other.wildcards: return False
    if self.in_port != other.in_port: return False
    if self.dl_src != other.dl_src: return False
    if self.dl_dst != other.dl_dst: return False
    if self.dl_vlan != other.dl_vlan: return False
    if self.dl_vlan_pcp != other.dl_vlan_pcp: return False
    if self.dl_type != other.dl_type: return False
    if self.nw_tos != other.nw_tos: return False
    if self.nw_proto != other.nw_proto: return False
    if self.nw_src != other.nw_src: return False
    if self.nw_dst != other.nw_dst: return False
    if self.tp_src != other.tp_src: return False
    if self.tp_dst != other.tp_dst: return False
    return True

  def __str__ (self):
    return self.__class__.__name__ + "\n  " + self.show('  ').strip()

  def show (self, prefix=''):
    def binstr (n):
      s = ''
      while True:
        s = ('1' if n & 1 else '0') + s
        n >>= 1
        if n == 0: break
      return s
    def safehex(n):
      if n is None:
        return "(None)"
      else:
        return hex(n)

    def show_wildcards(w):
      parts = [ k.lower()[len("OFPFW_"):]
                for (k,v) in mms_flow_wildcards_rev_map.iteritems()
                if v & w == v ]
      nw_src_bits = (w & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
      if nw_src_bits > 0:
        parts.append("nw_src(/%d)" % (32 - nw_src_bits))

      nw_dst_bits = (w & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
      if nw_dst_bits > 0:
        parts.append("nw_dst(/%d)" % (32 - nw_dst_bits))

      return "|".join(parts)

    outstr = ''
    outstr += prefix + 'wildcards: '
    outstr += show_wildcards(self.wildcards)
    outstr += ' (%s = %x)\n' % (binstr(self.wildcards), self.wildcards)
    def append (f, formatter=str):
      v = self.__getattr__(f)
      if v is None: return ''
      return prefix + f + ": " + formatter(v) + "\n"
    outstr += append('in_port')
    outstr += append('dl_src')
    outstr += append('dl_dst')
    outstr += append('dl_vlan')
    outstr += append('dl_vlan_pcp')
    outstr += append('dl_type', safehex)
    outstr += append('nw_tos')
    outstr += append('nw_proto')
    outstr += append('nw_src')
    outstr += append('nw_dst')
    outstr += append('tp_src')
    outstr += append('tp_dst')
    return outstr


@mirror_message("MMS_FLOWS_REPLY", 4)
class mms_flows_reply (mms_header):
  _MIN_LENGTH = 20
  def __init__ (self, **kw):
    mms_header.__init__(self)
    self.type = None # Guess
    self.flags = 0
    self.body = b''
    self._body_data = (None, None)
    initHelper(self, kw)

  @property
  def is_last_reply (self):
    return (self.flags & 1) == 0
  @is_last_reply.setter
  def is_last_reply (self, value):
    self.flags = self.flags & 0xfffe
    if not value:
      self.flags |= 1

  @property
  def body_data (self):
    if self._body_data[0] is not self.body:
      def _pack(b):
        return b.pack() if hasattr(b, 'pack') else b

      data = b''
      if is_listlike(self.body):
        for b in self.body:
          data += _pack(b)
      else:
        data = _pack(self.body)
      self._body_data = (self.body, data)
    return self._body_data[1]

  def of_convert_mms(self,other,dpid):
    self.dpid=dpid
    self.xid=other.xid
    self.type=other.type
    self.flags=other.flags
    self.body=other.body

  def pack (self):
    if self.type is None:
      if is_listlike(self.body):
        if len(self.body):
          b = self.body[0]
        else:
          b = None # Will fail below
      else:
        b = self.body
      if isinstance(b, mms_stats_body_base):
        self.type = b._type
      else:
        raise RuntimeError("Can't determine body type; specify it "
                           + "explicitly")

    assert self._assert()

    packed = b""
    packed += mms_header.pack(self)
    packed += struct.pack("!HH", self.type, self.flags)
    packed += self.body_data
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset,(self.type, self.flags) = _unpack("!HH", raw, offset)
    offset,packed = _read(raw, offset, length - self._MIN_LENGTH)
    t = _stats_type_to_class_info.get(self.type)
    if t is None:
      #FIXME: Put in a generic container?
      self.body = packed
    else:
      if t.reply is None:
        #FIXME: Put in a generic container?
        self.body = packed
      else:
        if not t.reply_is_list:
          self.body = t.reply()
          self.body.unpack(packed, 0, len(packed))
        else:
          prev_len = len(packed)
          self.body = []
          while len(packed):
            part = t.reply()
            off = part.unpack(packed, 0, len(packed))
            packed = packed[off:]
            assert len(packed) != prev_len
            prev_len = len(packed)
            self.body.append(part)

    assert length == len(self)
    return offset,length

  def __len__ (self):
    if isinstance(self.body, list):
      return self._MIN_LENGTH + sum(len(part) for part in self.body)
    return self._MIN_LENGTH + len(self.body)

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    if self.type != other.type: return False
    if self.flags != other.flags: return False
    if self.body != other.body: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'flags: ' + str(self.flags) + '\n'
    outstr += prefix + 'body:\n'
    body = self.body
    if not is_listlike(body):
      body = [body]
    for b in body:
      outstr += _format_body(b, prefix + '  ') + '\n'
    return outstr

@mirror_message("MMS_FILE_REPLY", 5)
class mms_file_reply (mms_header):
  _MIN_LENGTH = 48
  def __init__ (self, **kw):
    mms_header.__init__(self)
    self.port=0
    self.filename = "" # Guess
    self.filedata = b''
    initHelper(self, kw)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += mms_header.pack(self)
    packed += struct.pack("!H30s", self.port, self.filename)
    packed += self.filedata
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset,(self.port, filename) = _unpack("!H30s", raw, offset)
    self.filename=filename.strip(STR_NULL)
    offset,packed = _read(raw, offset, length - self._MIN_LENGTH)
    self.filedata=packed
    assert length == len(self)
    return offset,length

  def __len__ (self):
    return self._MIN_LENGTH + len(self.filedata)

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    if self.port != other.port: return False
    if self.filename != other.filename: return False
    if self.filedata != other.filedata: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    outstr += prefix + 'port: ' + str(self.port) + '\n'
    outstr += prefix + 'filename: ' + str(self.filename) + '\n'
    outstr += prefix + 'filedata:\n'
    outstr += _format_body(self.filedata, prefix + '  ') + '\n'
    return outstr

@mirror_message("MMS_PCAP_MESSAGE", 6)
class mms_pcap_message (mms_header):
  _MIN_LENGTH = 56
  def __init__ (self, **kw):
    mms_header.__init__(self)
    self.port=0
    self.filename = "" # Guess
    self.sec=0
    self.messagelength=0
    self.messagedata = b''
    initHelper(self, kw)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += mms_header.pack(self)
    packed += struct.pack("!H30sII", self.port, self.filename,self.sec,self.messagelength)
    packed += self.messagedata
    return packed

  def unpack (self, raw, offset=0):
    offset,length = self._unpack_header(raw, offset)
    offset,(self.port, filename,self.sec,self.messagelength) = _unpack("!H30sII", raw, offset)
    self.filename=filename.strip(STR_NULL)
    offset,packed = _read(raw, offset, length - self._MIN_LENGTH)
    self.messagedata=packed
    assert length == len(self)
    return offset,length

  def __len__ (self):
    return self._MIN_LENGTH + len(self.messagedata)

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if not mms_header.__eq__(self, other): return False
    if self.port != other.port: return False
    if self.filename != other.filename: return False
    if self.sec != other.sec: return False
    if self.messagelength != other.messagelength: return False
    if self.messagedata != other.messagedata: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'header: \n'
    outstr += mms_header.show(self, prefix + '  ')
    outstr += prefix + 'port: ' + str(self.port) + '\n'
    outstr += prefix + 'filename: ' + str(self.filename) + '\n'
    outstr += prefix + 'messagedata:\n'
    outstr += _format_body(self.messagedata, prefix + '  ') + '\n'
    return outstr

@mirror_stats_reply('OFPST_FLOW', 1,is_list = True)
class mms_flows_reply_body (mms_stats_body_base):
  _MIN_LENGTH = 88
  def __init__ (self, **kw):
    self.table_id = 0
    self.match = mms_match()
    self.duration_sec = 0
    self.duration_nsec = 0
    self.priority = OFP_DEFAULT_PRIORITY
    self.idle_timeout = 0
    self.hard_timeout = 0
    self.cookie = 0
    self.packet_count = 0
    self.byte_count = 0
    self.actions = []

  def _validate (self):
    if not isinstance(self.match, mms_match):
      return "match is not class ofp_match"
    return None

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HBB", len(self), self.table_id, 0)
    packed += self.match.pack()
    packed += struct.pack("!LLHHH", self.duration_sec,
                          self.duration_nsec, self.priority,
                          self.idle_timeout, self.hard_timeout)
    packed += _PAD6 # Pad
    packed += struct.pack("!QQQ", self.cookie, self.packet_count,
                          self.byte_count)
    for i in self.actions:
      packed += i.pack()
    return packed

  def unpack (self, raw, offset, avail):
    _offset = offset
    offset,(length, self.table_id, pad) = _unpack("!HBB", raw, offset)
    assert pad == 0
    offset = self.match.unpack(raw, offset)
    offset,(self.duration_sec, self.duration_nsec, self.priority,
            self.idle_timeout, self.hard_timeout) = \
            _unpack("!LLHHH", raw, offset)
    offset = _skip(raw, offset, 6)
    offset,(self.cookie, self.packet_count, self.byte_count) = \
        _unpack("!QQQ", raw, offset)
    assert (offset - _offset) == 48 + len(self.match)
    offset,self.actions = _unpack_actions(raw,
        length - (48 + len(self.match)), offset)
    assert offset - _offset == len(self)
    return offset

  def __len__ (self):
    l = 48 + len(self.match)
    for i in self.actions:
      l += len(i)
    return l

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if len(self) != len(other): return False
    if self.table_id != other.table_id: return False
    if self.match != other.match: return False
    if self.duration_sec != other.duration_sec: return False
    if self.duration_nsec != other.duration_nsec: return False
    if self.priority != other.priority: return False
    if self.idle_timeout != other.idle_timeout: return False
    if self.hard_timeout != other.hard_timeout: return False
    if self.cookie != other.cookie: return False
    if self.packet_count != other.packet_count: return False
    if self.byte_count != other.byte_count: return False
    if self.actions != other.actions: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'length: ' + str(len(self)) + '\n'
    outstr += prefix + 'table_id: ' + str(self.table_id) + '\n'
    outstr += prefix + 'match: \n'
    outstr += self.match.show(prefix + '  ')
    outstr += prefix + 'duration_sec: ' + str(self.duration_sec) + '\n'
    outstr += prefix + 'duration_nsec: ' + str(self.duration_nsec) + '\n'
    outstr += prefix + 'priority: ' + str(self.priority) + '\n'
    outstr += prefix + 'idle_timeout: ' + str(self.idle_timeout) + '\n'
    outstr += prefix + 'hard_timeout: ' + str(self.hard_timeout) + '\n'
    outstr += prefix + 'cookie: ' + str(self.cookie) + '\n'
    outstr += prefix + 'packet_count: ' + str(self.packet_count) + '\n'
    outstr += prefix + 'byte_count: ' + str(self.byte_count) + '\n'
    outstr += prefix + 'actions: \n'
    for obj in self.actions:
      outstr += obj.show(prefix + '  ')
    return outstr


'''
msg=mms_hello()
msg.pack()
print msg.show()

msg=mms_poxconnectionstates()
msg.connectionstates=0
msg.dpid=111
print msg.show()
msg1=mms_poxconnectionstates()
data=struct.pack("!BBHLQB", 1,1,17,12,1,1)
msg1.unpack(data)
print msg1.show()

msg=mms_topoly_reply()
link=Link(2,1,3,1);
msg.links.append(link)
link=Link(10,1,30,1);
msg.links.append(link)
msg.pack()
print msg.show()
msg1=mms_topoly_reply()
data=struct.pack("!BBHLBLB", 1,1,14,link.dpid1, link.port1,link.dpid2,link.port2)
msg1.unpack(data)
print msg1.linknum
print msg1.show()

msg=mms_topoly_request()
print msg.show()
msg1=mms_topoly_request()
print msg==msg1
print len(msg.body)
data=struct.pack("!BBH", 12, 20,4)
msg.unpack(data)
print msg.show()

link=Link(2,1,3,1);
print isinstance(link, bytes)
msg=mms_topoly_link()
#msg.data=struct.pack("!BB", 12, 20)
msg.data=struct.pack("!LBLB", link.dpid1, link.port1,link.dpid2,link.port2)
print msg.show()
print msg.header_type,binascii.hexlify(msg.data)
msg1=mms_topoly_link()
#msg1.data=struct.pack("!BB", 12, 20)
#print msg==msg1
data=struct.pack("!BBHBB", 1,1,6,12, 20)
print msg1.unpack(data,0)
print msg1.header_type,binascii.hexlify(msg1.data)


link=Link(2,1,3,1);
print isinstance(link, bytes)
msg=mms_topoly_link()
msg.link=link
print msg.link
print len(msg)
#msg.pack()
print binascii.hexlify(msg.pack())
print msg.show()
msg1=mms_topoly_link()
data=struct.pack("!BBHLBLB", 1,1,14,link.dpid1, link.port1,link.dpid2,link.port2)
print binascii.hexlify(data)
print msg1.unpack(data,0)
print msg1.show()
print msg==msg1
hell=mms_hello()
print hell.show()
'''
@mirror_action('OFPAT_OUTPUT', 0)
class mms_action_output (mms_action_base):
  def __init__ (self, **kw):
    self.port = None # Purposely bad -- require specification
    self.max_len = 0xffFF

    initHelper(self, kw)

  def pack (self):
    if self.port != OFPP_CONTROLLER:
      self.max_len = 0

    assert self._assert()

    packed = b""
    packed += struct.pack("!HHHH", self.type, len(self), self.port,
                          self.max_len)
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.port, self.max_len) = \
        _unpack("!HHHH", raw, offset)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.port != other.port: return False
    if self.max_len != other.max_len: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'port: ' + str(self.port) + '\n'
    outstr += prefix + 'max_len: ' + str(self.max_len) + '\n'
    return outstr

@mirror_action('OFPAT_ENQUEUE', 11)
class mms_action_enqueue (mms_action_base):
  def __init__ (self, **kw):
    self.port = None # Require user to set
    self.queue_id = 0

    initHelper(self, kw)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HHH", self.type, len(self), self.port)
    packed += _PAD6 # Pad
    packed += struct.pack("!L", self.queue_id)
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.port) = _unpack("!HHH", raw, offset)
    offset = _skip(raw, offset, 6)
    offset,(self.queue_id,) = _unpack("!L", raw, offset)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 16

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.port != other.port: return False
    if self.queue_id != other.queue_id: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'port: ' + str(self.port) + '\n'
    outstr += prefix + 'queue_id: ' + str(self.queue_id) + '\n'
    return outstr

@mirror_action('OFPAT_STRIP_VLAN', 3)
class mms_action_strip_vlan (mms_action_base):
  def __init__ (self):
    pass

  def pack (self):
    packed = struct.pack("!HHi", self.type, len(self), 0)
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length) = _unpack("!HH", raw, offset)
    offset = _skip(raw, offset, 4)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    return outstr

@mirror_action('OFPAT_SET_VLAN_VID', 1)
class mms_action_vlan_vid (mms_action_base):
  def __init__ (self, **kw):
    self.vlan_vid = 0

    initHelper(self, kw)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HHH", self.type, len(self), self.vlan_vid)
    packed += _PAD2 # Pad
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.vlan_vid) = \
        _unpack("!HHH", raw, offset)
    offset = _skip(raw, offset, 2)
    #TODO: check length for this and other actions
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.vlan_vid != other.vlan_vid: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'vlan_vid: ' + str(self.vlan_vid) + '\n'
    return outstr

@mirror_action('OFPAT_SET_VLAN_PCP', 2)
class mms_action_vlan_pcp (mms_action_base):
  def __init__ (self, **kw):
    self.vlan_pcp = 0

    initHelper(self, kw)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HHB", self.type, len(self), self.vlan_pcp)
    packed += _PAD3 # Pad
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.vlan_pcp) = \
        _unpack("!HHB", raw, offset)
    offset = _skip(raw, offset, 3)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.vlan_pcp != other.vlan_pcp: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'vlan_pcp: ' + str(self.vlan_pcp) + '\n'
    return outstr

@mirror_action('OFPAT_SET_DL_DST', 5)
@mirror_action('OFPAT_SET_DL_SRC', 4)
class mms_action_dl_addr (mms_action_base):
  @classmethod
  def set_dst (cls, dl_addr = None):
    return cls(OFPAT_SET_DL_DST, dl_addr)
  @classmethod
  def set_src (cls, dl_addr = None):
    return cls(OFPAT_SET_DL_SRC, dl_addr)

  def __init__ (self, type = None, dl_addr = None):
    """
    'type' should be OFPAT_SET_DL_SRC or OFPAT_SET_DL_DST.
    """
    self.type = type
    self.dl_addr = EMPTY_ETH

    if dl_addr is not None:
      self.dl_addr = EthAddr(dl_addr)

  def _validate (self):
    if (not isinstance(self.dl_addr, EthAddr)
        and not isinstance(self.dl_addr, bytes)):
      return "dl_addr is not string or EthAddr"
    if isinstance(self.dl_addr, bytes) and len(self.dl_addr) != 6:
      return "dl_addr is not of size 6"
    return None

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HH", self.type, len(self))
    if isinstance(self.dl_addr, EthAddr):
      packed += self.dl_addr.toRaw()
    else:
      packed += self.dl_addr
    packed += _PAD6
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length) = _unpack("!HH", raw, offset)
    offset,self.dl_addr = _readether(raw, offset)
    offset = _skip(raw, offset, 6)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 16

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.dl_addr != other.dl_addr: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'dl_addr: ' + str(self.dl_addr) + '\n'
    return outstr

@mirror_action('OFPAT_SET_NW_DST', 7)
@mirror_action('OFPAT_SET_NW_SRC', 6)
class mms_action_nw_addr (mms_action_base):
  @classmethod
  def set_dst (cls, nw_addr = None):
    return cls(OFPAT_SET_NW_DST, nw_addr)
  @classmethod
  def set_src (cls, nw_addr = None):
    return cls(OFPAT_SET_NW_SRC, nw_addr)

  def __init__ (self, type = None, nw_addr = None):
    """
    'type' should be OFPAT_SET_NW_SRC or OFPAT_SET_NW_DST
    """
    self.type = type

    if nw_addr is not None:
      self.nw_addr = IPAddr(nw_addr)
    else:
      self.nw_addr = IPAddr(0)

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HHl", self.type, len(self),
                          self.nw_addr.toSigned())
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length) = _unpack("!HH", raw, offset)
    offset,self.nw_addr = _readip(raw, offset)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.nw_addr != other.nw_addr: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'nw_addr: ' + str(self.nw_addr) + '\n'
    return outstr

@mirror_action('OFPAT_SET_NW_TOS', 8)
class mms_action_nw_tos (mms_action_base):
  def __init__ (self, nw_tos = 0):
    self.nw_tos = nw_tos

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HHB", self.type, len(self), self.nw_tos)
    packed += _PAD3
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.nw_tos) = _unpack("!HHB", raw, offset)
    offset = _skip(raw, offset, 3)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.nw_tos != other.nw_tos: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'nw_tos: ' + str(self.nw_tos) + '\n'
    return outstr

@mirror_action('OFPAT_SET_TP_DST', 10)
@mirror_action('OFPAT_SET_TP_SRC', 9)
class mms_action_tp_port (mms_action_base):
  @classmethod
  def set_dst (cls, tp_port = None):
    return cls(OFPAT_SET_TP_DST, tp_port)
  @classmethod
  def set_src (cls, tp_port = None):
    return cls(OFPAT_SET_TP_SRC, tp_port)

  def __init__ (self, type=None, tp_port = 0):
    """
    'type' is OFPAT_SET_TP_SRC/DST
    """
    self.type = type
    self.tp_port = tp_port

  def pack (self):
    assert self._assert()

    packed = b""
    packed += struct.pack("!HHH", self.type, len(self), self.tp_port)
    packed += _PAD2
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.tp_port) = \
        _unpack("!HHH", raw, offset)
    offset = _skip(raw, offset, 2)
    assert offset - _offset == len(self)
    return offset

  @staticmethod
  def __len__ ():
    return 8

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.tp_port != other.tp_port: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'tp_port: ' + str(self.tp_port) + '\n'
    return outstr

@mirror_action('OFPAT_VENDOR', 65535)
class mms_action_vendor_generic (mms_action_base):
  def __init__ (self, **kw):
    self.vendor = 0
    self.body = b""

    initHelper(self, kw)

  def _pack_body (self):
    if hasattr(self.body, 'pack'):
      return self.body.pack()
    else:
      return bytes(self.body)

  def pack (self):
    assert self._assert()

    body = self._pack_body()

    packed = b""
    packed += struct.pack("!HHL", self.type, 8 + len(body), self.vendor)
    packed += body
    return packed

  def unpack (self, raw, offset=0):
    _offset = offset
    offset,(self.type, length, self.vendor) = _unpack("!HHL", raw, offset)
    offset,self.body = _read(raw, offset, length - 8)
    assert offset - _offset == len(self)
    return offset

  def __len__ (self):
    return 8 + len(self._pack_body())

  def __eq__ (self, other):
    if type(self) != type(other): return False
    if self.type != other.type: return False
    if len(self) != len(other): return False
    if self.vendor != other.vendor: return False
    return True

  def show (self, prefix=''):
    outstr = ''
    outstr += prefix + 'type: ' + str(self.type) + '\n'
    outstr += prefix + 'len: ' + str(len(self)) + '\n'
    outstr += prefix + 'vendor: ' + str(self.vendor) + '\n'
    return outstr


def make_type_to_unpacker_table ():
  """
  Returns a list of unpack methods.

  The resulting list maps OpenFlow types to functions which unpack
  data for those types into message objects.
  """

  top = len(_message_type_to_class)

  r = [_message_type_to_class[i].unpack_new for i in range(0, top)]

  return r


def _init ():
  def formatMap (name, m):
    o = name + " = {\n"
    vk = sorted([(v,k) for k,v in m.iteritems()])
    maxlen = 2 + len(reduce(lambda a,b: a if len(a)>len(b) else b,
                            (v for k,v in vk)))
    fstr = "  %-" + str(maxlen) + "s : %s,\n"
    for v,k in vk:
      o += fstr % ("'" + k + "'",v)
    o += "}"
    return o
  """
  maps = []
  for k,v in globals().iteritems():
    if k.startswith("ofp_") and k.endswith("_map") and type(v) == dict:
      maps.append((k,v))
  for name,m in maps:
    rev = {}
    name = name[:-4]
    names = globals()[name]
    for n in names:
      rev[n] = globals()[n]

    globals()[name + '_rev_map'] = rev
    print(formatMap(name + "_rev_map", rev))
  return
  """
  maps = []
  for k,v in globals().iteritems():
    if (k.startswith("mms_") and k.endswith("_rev_map")
        and type(v) == dict):
      maps.append((k[:-8],v))
      #print k[:-8],v
  #print maps
  for name,m in maps:
    # Try to generate forward maps
    forward = dict(((v,k) for k,v in m.iteritems()))
    #print forward
    if len(forward) == len(m):
      if name + "_map" not in globals():
        globals()[name + "_map"] = forward
    else:
      print(name + "_rev_map is not a map")

    # Try to generate lists
    v = m.values()
    v.sort()
    if v[-1] != len(v)-1:
      # Allow ones where the last value is a special value (e.g., VENDOR)
      del v[-1]
    if len(v) > 0 and v[0] == 0 and v[-1] == len(v)-1:
      globals()[name] = v

    # Generate gobals
    for k,v in m.iteritems():
      globals()[k] = v


_init()

OFP_DEFAULT_PRIORITY = 0x8000

mms_match_data = {
  'in_port' : (0, OFPFW_IN_PORT),
  'dl_src' : (EMPTY_ETH, OFPFW_DL_SRC),
  'dl_dst' : (EMPTY_ETH, OFPFW_DL_DST),
  'dl_vlan' : (0, OFPFW_DL_VLAN),
  'dl_vlan_pcp' : (0, OFPFW_DL_VLAN_PCP),
  'dl_type' : (0, OFPFW_DL_TYPE),
  'nw_tos' : (0, OFPFW_NW_TOS),
  'nw_proto' : (0, OFPFW_NW_PROTO),
  'nw_src' : (0, OFPFW_NW_SRC_ALL),
  'nw_dst' : (0, OFPFW_NW_DST_ALL),
  'tp_src' : (0, OFPFW_TP_SRC),
  'tp_dst' : (0, OFPFW_TP_DST),
}
'''
match=mms_match()
print (match.show())
match.get_nw_dst()
match.clone()
match.flip()
print(match._dl_dst)
match._prereq_warning()
match.fix()
match.wildcards=1
match.is_wildcarded
match._in_port
match.__len__()
match.hash_code()
data=match.pack()
match.unpack(data)

reply=mms_flows_reply_body()
reply.pack()
print(reply.show())
reply.match
reply.actions
reply.byte_count
reply.cookie
#reply.unpack
flws=mms_flows_reply(body=mms_flows_reply_body())
flws.type=1
data=flws.pack()
flws.unpack(data)
flws._assert()
flws._body_data
flws.body
print(flws.show())

action=mms_action_output(port = OFPP_FLOOD)
data=action.pack()
action.unpack(data)
action.type
action.port
print(action.show())

action=mms_action_enqueue(port = OFPP_FLOOD,queue_id=1)
print(action.show())

action=mms_action_strip_vlan()
print(action.show())

action=mms_action_dl_addr(type=1)
print(action.show())
action.pack()


action=mms_action_nw_addr()
print(action.show())
'''