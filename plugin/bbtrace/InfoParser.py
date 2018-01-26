import re
import json
import csv


class InfoParser:
    def __init__(self, infoname):
        self.infoname = infoname
        if not re.match(r'.*\.log\.info$', infoname):
            raise Exception("Need .log.info file")

    def load(self):

        fp = open(self.infoname, 'r')
        json_rows = json.load(fp)
        fp.close()

        basic_blocks = {}

        for row in json_rows:
            if len(row) and 'block_entry' in row:
                entry = int(row['block_entry'], 0)
                basic_blocks[entry] = {
                    'entry': entry,
                    'end': int(row['block_end'], 0),
                    'module': int(row['module_start_ref'], 0),
                    'last_pc': int(row['last_pc'], 0),
                    'last_asm': row['last_asm']
                }
        self.basic_blocks = basic_blocks

    def flow(self):
        flowname = re.sub(r'\.log\.info$', '.log.flow', self.infoname)

        fp = open(flowname, 'r')
        flowreader = csv.reader(fp, skipinitialspace=True)
        for row in flowreader:
            block_addr = int(row[0], 0)
            last_block_addr = int(row[1], 0)
            occurence = int(row[2])
            if last_block_addr in self.basic_blocks:
                basic_block = self.basic_blocks[last_block_addr]
                disasm = basic_block['last_asm']
                if re.match(r'(j|call)', disasm):
                    print(hex(last_block_addr), '->', hex(block_addr), disasm, occurence)

        fp.close()

