import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugin')))

from bbtrace.InfoParser import InfoParser


fname = sys.argv[1]

infoparser = InfoParser(fname)

infoparser.load()
infoparser.flow()
