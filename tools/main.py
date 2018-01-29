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

def print_stack(stack):
    for s in stack:
        print("entry: 0x%08x, end: 0x%08x, 0x%x %s" % (s['entry'], s['end'], s['last_pc'], s['last_asm']))

while tracelog.max_d is None:
    tdat = tracelog.get_data(d)
    if not tdat:
        break

    tid = tdat.data['thread']
    if tid not in stacks:
        stacks[tid] = []
    if tid not in lasts:
        lasts[tid] = (None, None)

    print(tdat)

    for addr in tdat.unpack():
        block = infoparser.basic_blocks[addr] if addr in infoparser.basic_blocks else None
        symbol = infoparser.symbols[addr] if addr in infoparser.symbols else None

        last_addr, last_block = lasts[tid]

        lasts[tid] = (addr, block)

        if not last_addr: continue

        last_block = infoparser.basic_blocks[last_addr] if last_addr in infoparser.basic_blocks else None
        last_symbol = infoparser.symbols[last_addr] if last_addr in infoparser.symbols else None

        # block -> block
        if last_block and block:
            ## print("0x%08x %s -> 0x%08x" % (last_block['last_pc'], last_block['last_asm'], addr))
            if re.match(r'call', last_block['last_asm']):
                if addr != last_block['end']:
                    stacks[tid].append(last_block)

            elif re.match(r'ret', last_block['last_asm']):
                if len(stacks[tid]):
                    popped = stacks[tid][-1]
                    if popped['end'] == addr:
                        stacks[tid].pop()
                    else:
                        print("-------------------------------")
                        print_stack(stacks[tid])
                        print("-------------------------------")
                else:
                    raise Exception("Return on empty stacks")

        # block -> symbol
        elif last_block and symbol:
            print("0x%08x %s -> 0x%08x %s" % (last_block['last_pc'], last_block['last_asm'], addr, symbol['name']))
            if re.match(r'call', last_block['last_asm']):
                stacks[tid].append(last_block)

        # symbol -> block
        elif last_symbol and block:
            print("0x%08x %s -> 0x%08x" % (last_addr, last_symbol['name'], addr))

            if len(stacks[tid]):
                popped = stacks[tid][-1]
                if popped['end'] == addr:
                    stacks[tid].pop()
        elif last_symbol and symbol:
            print("0x%08x %s -> @ 0x%08x %s" % (last_addr, last_symbol['name'], addr, symbol['name']))

        else:
            print("-- @ 0x%08x -> @ 0x%08x" % (last_addr, addr))


    print("===================================")
    d += 1
