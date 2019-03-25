import sys
import os
import re
import struct

class FlameGraphReader:
    def __init__(self, filename):
        self.filename = filename
        self.roots = None

    def parse(self):
        callname = self.filename + ".fgraph"
        if not os.path.exists(callname):
            print "Unable to open", callname
            return False

        print "Parse file", callname
        self.fp = open(callname, 'rb')

        self.get_roots()

    def _get_pkt_tree(self):
        fp = self.fp
        p = fp.tell()
        s = fp.read(8)
        if s is None or len(s) == 0: return False

        x = struct.unpack('<II', s)
        return {
            'addr': x[0],
            'size': x[1],
            'off': p
        }

    def get_children(self, parent):
        fp = self.fp

        SIZEOF_tree = 8
        children = []
        off = 0 if parent['off'] is None else parent['off'] + SIZEOF_tree
        fp.seek(off, os.SEEK_SET)
        size = 1

        while parent['size'] is None or parent['size'] > size:
            tree = self._get_pkt_tree()
            if not tree: break

            children.append(tree)
            size += tree['size']

            fp.seek(SIZEOF_tree * (tree['size'] - 1), os.SEEK_CUR)

        return children

    def get_roots(self):
        if self.roots is None:
            self.roots = self.get_children({
                'addr': None,
                'size': None,
                'off': None
            })

        return self.roots

    def draw(self, d, max_x):
        return {}
