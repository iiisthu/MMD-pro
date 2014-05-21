__author__ = 'zhidoubleq'
import struct
import collections

def dpid_to_str (dpid, alwaysLong = False):
  """
  Convert a DPID from a long into into the canonical string form.
  """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = '-'.join(['%02x' % (ord(x),) for x in dpid[2:]])

  if alwaysLong or dpid[0:2] != (b'\x00'*2):
    r += '|' + str(struct.unpack('!H', dpid[0:2])[0])

  return r

def dpid_to_mac (dpid):
  """
  Convert a DPID from a long into into the canonical string form.
  """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = ':'.join(['%02x' % (ord(x),) for x in dpid[2:]])


  return r

def dpid_to_mininet (dpid):
  """
  Convert a DPID from a long into into the canonical string form.
  """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = ''.join(['%02x' % (ord(x),) for x in dpid[:]])


  return r

def dpid_to_filename (dpid, port):
  """
  Convert a DPID from a long into into the canonical string form.
  """
  if type(dpid) is long or type(dpid) is int:
    # Not sure if this is right
    dpid = struct.pack('!Q', dpid)

  assert len(dpid) == 8

  r = ''.join(['%02x' % (ord(x),) for x in dpid[2:]])

  r += '_' + str(port)

  return r
def filename_to_dpid (s):
  """
  Convert a DPID in the canonical string form into a long int.
  """
  if s.lower().startswith("0x"):
    s = s[2:]
  s = s.replace("-", "").split("_", 2)
  a = int(s[0], 16)

  if a > 0xffFFffFFffFF:
    b = a >> 48
    a &= 0xffFFffFFffFF
  else:
    b = 0
  if len(s) == 2:
    b = int(s[1])
  return a, b


def is_listlike (o):
  """
  Is this a sequence that isn't like a string or bytes?
  """
  if isinstance(o, (bytes,str,bytearray)): return False
  return isinstance(o, collections.Iterable)

def init_helper (obj, kw):
  """
  Helper for classes with attributes initialized by keyword arguments.

  Inside a class's __init__, this will copy keyword arguments to fields
  of the same name.  See libopenflow for an example.
  """
  for k,v in kw.iteritems():
    if not hasattr(obj, k):
      raise TypeError(obj.__class__.__name__ + " constructor got "
      + "unexpected keyword argument '" + k + "'")
    setattr(obj, k, v)
initHelper = init_helper # Deprecated

def assert_type(name, obj, types, none_ok=True):
  """
  Assert that a parameter is of a given type.

  Raise an Assertion Error with a descriptive error msg if not.

  name: name of the parameter for error messages
  obj: parameter value to be checked
  types: type or list or tuple of types that is acceptable
  none_ok: whether 'None' is an ok value
  """
  if obj is None:
    if none_ok:
      return True
    else:
      raise AssertionError("%s may not be None" % name)

  if not isinstance(types, (tuple, list)):
    types = [ types ]

  for cls in types:
    if isinstance(obj, cls):
      return True
  allowed_types = "|".join(map(lambda x: str(x), types))
  stack = traceback.extract_stack()
  stack_msg = "Function call %s() in %s:%d" % (stack[-2][2],
                                               stack[-3][0], stack[-3][1])
  type_msg = ("%s must be instance of %s (but is %s)"
              % (name, allowed_types , str(type(obj))))

  raise AssertionError(stack_msg + ": " + type_msg)

spack=struct.pack('!1s', '')
sunpack,=struct.unpack('!1s',spack)
STR_NULL=str(sunpack)


