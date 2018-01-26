import sys
from bbtrace.InfoParser import InfoParser


fname = sys.argv[1]

infoparser = InfoParser(fname)

infoparser.load()
infoparser.flow()
