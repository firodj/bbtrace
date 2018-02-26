import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugin')))

from bbtrace.InfoParser import InfoParser
from bbtrace.FlameGraphReader import FlameGraphReader

fname = sys.argv[1]

infoparser = InfoParser(fname)

infoparser.load()

flamegraph = FlameGraphReader()
# infoparser.flow()

# tracelog = TraceLog(fname)

# callstack = CallStackBuilder(infoparser, tracelog)
# callstack.parse()
# callstack.build()

# lines = callstack.draw(0, 100)
#
# rows = lines.keys()
# rows.sort()
# for y in rows:
#     print lines[y]
