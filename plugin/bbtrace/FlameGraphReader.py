import sys
import os
import re
import struct

class FlameGraphReader:
    SIZEOF_tree = 8

    def __init__(self, filename):
        self.filename = filename
        self.roots = None
        self.symbols = {}
        self.ofs_tree = None

    def parse(self):
        callname = self.filename + ".fgraph"
        if not os.path.exists(callname):
            print "Unable to open", callname
            return False

        print "Parse file", callname
        self.fp = open(callname, 'rb')

        self.parse_symbols()

        self.ofs_tree = self.fp.tell()

        self.get_roots()

    def parse_symbols(self):
        fp = self.fp
        s = fp.read(4)
        x = struct.unpack('<I', s)
        i = x[0]
        while i:
            s = fp.read(4 + 1)
            addr, len_name  = struct.unpack('<IB', s)
            name = fp.read(len_name)
            self.symbols[addr] = name
            i -= 1
        # Debug
        print self.symbols

    def _get_pkt_tree(self):
        fp = self.fp
        p = fp.tell()
        s = fp.read(self.SIZEOF_tree)
        if s is None or len(s) == 0: return False

        x = struct.unpack('<II', s)
        return {
            'addr': x[0],
            'size': x[1],
            'off': p
        }

    def get_children(self, parent):
        fp = self.fp

        children = []
        off = self.ofs_tree if parent['off'] is None else parent['off'] + self.SIZEOF_tree
        fp.seek(off, os.SEEK_SET)
        size = 1

        while parent['size'] is None or parent['size'] > size:
            tree = self._get_pkt_tree()
            if not tree: break

            children.append(tree)
            size += tree['size']

            fp.seek(self.SIZEOF_tree * (tree['size'] - 1), os.SEEK_CUR)

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
