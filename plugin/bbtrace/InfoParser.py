import re
import json
import csv
from collections import OrderedDict


class InfoParser:
    def __init__(self, infoname):
        self.infoname = infoname
        if not re.match(r'.*\.log\.info$', infoname):
            raise Exception("Need .log.info file")

        self.basic_blocks = OrderedDict()
        self.flows = {}
        self.symbols = OrderedDict()

    def load(self):

        fp = open(self.infoname, 'r')
        json_rows = json.load(fp)
        fp.close()

        basic_blocks = {}
        symbols = {}

        csvname = re.sub(r'\.log\.info$', '.log.csv', self.infoname)
        fcsv = open(csvname, 'wb')
        infowriter = csv.writer(fcsv)

        for row in json_rows:
            if not len(row): continue

            if 'block_entry' in row:
                entry = int(row['block_entry'], 0)
                block = {
                    'type': 'block',
                    'entry': entry,
                    'end': int(row['block_end'], 0),
                    'module': int(row['module_start_ref'], 0),
                    'last_pc': int(row['last_pc'], 0),
                    'last_asm': row['last_asm']
                }
                infowriter.writerow([
                    block['type'],
                    block['entry'],
                    block['module'],
                    block['end'],
                    block['last_pc'],
                    block['last_asm']
                ])
                basic_blocks[entry] = block

            elif 'symbol_entry' in row:
                entry = int(row['symbol_entry'], 0)
                symbol = {
                    'type': 'symbol',
                    'entry': entry,
                    'module': int(row['module_start_ref'], 0),
                    'name': row['symbol_name'],
                    'ordinal': row['symbol_ordinal']
                }
                infowriter.writerow([
                    symbol['type'],
                    symbol['entry'],
                    symbol['module'],
                    symbol['ordinal'],
                    symbol['name']
                ])
                symbols[entry] = symbol

            elif 'module_entry' in row:
                infowriter.writerow([
                    'module',
                    int(row['module_entry'], 0),
                    int(row['module_start'], 0),
                    int(row['module_end'], 0),
                    row['module_name'],
                    row['module_path']
                ])

            elif 'import_module_name' in row:
                print row
                pass
            elif 'fault_address' in row:
                print row
                pass
            else:
                print row
                raise Exception()

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
