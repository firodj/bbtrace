import sys
import re
import json
import csv


fname = sys.argv[1]
if not re.match(r'.*\.log\.info$', fname):
    raise Exception("Need .log.info file")

fp = open(fname, 'r')
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

# print(basic_blocks)
fname2 = re.sub(r'\.log\.info$', '.log.flow', fname)

fp = open(fname2, 'r')
flowreader = csv.reader(fp, skipinitialspace=True)
for row in flowreader:
    block_addr = int(row[0], 0)
    last_block_addr = int(row[1], 0)
    occurence = int(row[2])
    if last_block_addr in basic_blocks:
        basic_block = basic_blocks[last_block_addr]
        disasm = basic_block['last_asm']
        if re.match(r'(j|call)', disasm):
            print(hex(last_block_addr), '->', hex(block_addr), disasm, occurence)

fp.close()
