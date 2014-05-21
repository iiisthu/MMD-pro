from pox.core import core                     # Main POX object
#class test1(object):

log = core.getLogger()
def _go_up (event):
  # Event handler called when POX goes into up state
  # (we actually listen to the event in launch() below)
  log.info("Skeleton application ready (to do nothing).")


def launch (foo, bar = False):
  """
  The default launcher just logs its arguments
  """

  print "test"
  log.warn("Foo: %s (%s)", foo, type(foo))
  log.warn("Bar: %s (%s)", bar, type(bar))

  core.addListenerByName("UpEvent", _go_up)
