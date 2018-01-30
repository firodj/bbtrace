import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugin')))

from bbtrace.InfoParser import InfoParser
from bbtrace.TraceLog import TraceLog


fname = sys.argv[1]

infoparser = InfoParser(fname)

infoparser.load()
# infoparser.flow()

tracelog = TraceLog(fname)

d = 0
stacks = {}
lasts = {}

debug = False

class LogStack:
    def __init__(self, thread):
        self.thread = thread
        self.stack = []

    def append(self, item):
        self.stack.append(item)

    def pop(self):
        if len(self.stack):
            item = self.stack.pop()
            return item

    def pop_into(self, addr):
        j = None
        for i in xrange(len(self.stack)-1, -1, -1):
            item = self.stack[i]
            if item['type'] != 'block': continue
            if item['end'] == addr:
                j = i
                break

        if j is not None:
            self.stack = self.stack[:j]
            return item

        raise Exception("Fail to pop into 0x%08x" % (addr,))

    def peek(self):
        if len(self.stack):
            item = self.stack[-1]
            return item

    def peek_block(self, addr):
        for i in xrange(len(self.stack)-1, -1, -1):
            item = self.stack[i]
            if item['type'] == 'block' and item['end'] == addr:
                return item

    def info(self):
        print("thread: 0x%08x" % (self.thread,))
        for s in self.stack:
            if s['type'] == 'block':
                print("entry: 0x%08x, end: 0x%08x, 0x%x %s" % (s['entry'], s['end'], s['last_pc'], s['last_asm']))
            if s['type'] == 'symbol':
                print("entry: 0x%08x, name: %s" % (s['entry'], s['name']))


while tracelog.max_d is None:
    tdat = tracelog.get_data(d)
    if not tdat:
        break

    tid = tdat.data['thread']
    if tid not in stacks:
        stacks[tid] = LogStack(tid)
    if tid not in lasts:
        lasts[tid] = (None, None)

    print(tdat)

    for addr in tdat.unpack():
        block = infoparser.basic_blocks[addr] if addr in infoparser.basic_blocks else None
        symbol = infoparser.symbols[addr] if addr in infoparser.symbols else None

        last_addr, last_block = lasts[tid]

        lasts[tid] = (addr, block)

        if not last_addr:
            print("Start: 0x%08x" % (addr,))
            continue

        last_block = infoparser.basic_blocks[last_addr] if last_addr in infoparser.basic_blocks else None
        last_symbol = infoparser.symbols[last_addr] if last_addr in infoparser.symbols else None

        # block -> block
        if last_block and block:

            if debug:
                print("0x%08x %s -> 0x%08x" % (last_block['last_pc'], last_block['last_asm'], addr))

            if re.match(r'call', last_block['last_asm']):
                if addr != last_block['end']:
                    stacks[tid].append(last_block)

            elif re.match(r'ret', last_block['last_asm']):
                item = stacks[tid].peek_block(addr)
                if item:
                    stacks[tid].pop_into(addr)
                else:
                    print("------------------------>> 0x%08x" % (addr,))
                    stacks[tid].info()
                    print("-------------------------------")

        # block -> symbol
        elif last_block and symbol:

            if debug:
                print("0x%08x %s -> 0x%08x %s" % (last_block['last_pc'], last_block['last_asm'], addr, symbol['name']))

            if re.match(r'call', last_block['last_asm']):
                stacks[tid].append(last_block)

        # symbol -> block
        elif last_symbol and block:

            if debug:
                print("0x%08x %s -> 0x%08x" % (last_addr, last_symbol['name'], addr))

            item = stacks[tid].peek_block(addr)
            if item:
                stacks[tid].pop_into(addr)
            else:
                stacks[tid].append(last_symbol)
                print("------------------------>> 0x%08x" % (addr,))
                stacks[tid].info()
                print("-------------------------------")

        elif last_symbol and symbol:

            if debug:
                print("0x%08x %s -> @ 0x%08x %s" % (last_addr, last_symbol['name'], addr, symbol['name']))

            stacks[tid].append(last_symbol)

        else:
            print("-- @ 0x%08x -> @ 0x%08x" % (last_addr, addr))


    print("===================================[%d]" % (d,))
    d += 1

for tid, stack in stacks.iteritems():
    stack.info()
