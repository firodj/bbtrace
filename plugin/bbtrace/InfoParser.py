import re
import json
import csv
from collections import OrderedDict


class InfoParser:
    def __init__(self, infoname):
        self.infoname = infoname
        if not re.match(r'.*\.log\.csv$', infoname):
            raise Exception("Need .log.csv file")

        self.basic_blocks = OrderedDict()
        self.flows = {}
        self.symbols = OrderedDict()

    def load(self):
        basic_blocks = {}
        symbols = {}

        fcsv = open(self.infoname, 'r')
        inforeader = csv.reader(fcsv, skipinitialspace=True)

        for row in inforeader:
            if not len(row): continue

            if 'block' == row[0]:
                entry = int(row[1], 0)
                block = {
                    'type': row[0],
                    'entry': entry,
                    'module': int(row[2], 0),
                    'end': int(row[3], 0),
                    'last_pc': int(row[4], 0),
                    'last_asm': row[5]
                }
                basic_blocks[entry] = block

            elif 'symbol' == row[0]:
                entry = int(row[1], 0)
                symbol = {
                    'type': 'symbol',
                    'entry': entry,
                    'module': int(row[2], 0),
                    'ordinal': row[3],
                    'name': row[4],
                }
                symbols[entry] = symbol

        self.basic_blocks = basic_blocks
        self.symbols = symbols

        fcsv.close()

    def flow(self):
        flowname = re.sub(r'\.log\.info$', '.log.flow', self.infoname)

        fp = open(flowname, 'r')
        flowreader = csv.reader(fp, skipinitialspace=True)
        flows = {}

        for row in flowreader:
            block_addr = int(row[0], 0)
            last_block_addr = int(row[1], 0)
            occurence = int(row[2])

            if block_addr not in self.basic_blocks:
                continue

            if last_block_addr not in self.basic_blocks:
                continue

            before_basic_block = self.basic_blocks[last_block_addr]

            if block_addr == before_basic_block['end']:
                continue

            disasm = before_basic_block['last_asm']
            flowtype = None

            if re.match(r'j\w', disasm):
                flowtype = 'fl_JN'
            elif re.match(r'call', disasm):
                flowtype = 'fl_CN'
            else:
                continue

            if block_addr not in flows:
                flows[block_addr] = {}

            before_pc = before_basic_block['last_pc']
            flows[block_addr][before_pc] = flowtype

        fp.close()

        self.flows = flows
