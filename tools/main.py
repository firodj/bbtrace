import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugin')))

from bbtrace.InfoParser import InfoParser
from bbtrace.TraceLog import TraceLog


fname = sys.argv[1]

# infoparser = InfoParser(fname)
#
# infoparser.load()
# infoparser.flow()

tracelog = TraceLog(fname)

tdat = tracelog.get_data(0)

print tdat.get_trace(1048575)
