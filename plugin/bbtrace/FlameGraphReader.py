import sys
import os
import re


class FlameGraphReader:
    def __init__(self, infoparser):
        self.infoparser = infoparser

    def parse(self):
        callname = re.sub(r'\.log\.csv$', '.log.cbin', self.infoparser.infoname)
        if not os.path.exists(callname):
            return False

        fp = open(callname, 'rb')
        fp.close()

    def draw(self, d, max_x):
        return {}
