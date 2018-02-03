import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugin')))

from bbtrace.InfoParser import InfoParser
from bbtrace.TraceLog import TraceLog
from bbtrace.CallStackBuilder import CallStackBuilder


fname = sys.argv[1]

infoparser = InfoParser(fname)

infoparser.load()
# infoparser.flow()

tracelog = TraceLog(fname)

callstack = CallStackBuilder(infoparser, tracelog)
callstack.parse()
callstack.draw(90)
#callstack.build()
