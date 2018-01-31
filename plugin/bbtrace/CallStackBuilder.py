import sys
import os
import re
from InfoParser import InfoParser
from TraceLog import TraceLog
import json


class LogStack:
	def __init__(self, thread):
		self.thread = thread
		self.stack = []

	def append(self, item):
		self.stack.append(item)

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
		for item in self.stack:
			if item['type'] == 'block':
				print("entry: 0x%08x, end: 0x%08x, 0x%x %s" % (item['entry'], item['end'], item['last_pc'], item['last_asm']))
			if item['type'] == 'symbol':
				print("entry: 0x%08x, name: %s" % (item['entry'], item['name']))


class CallStackBuilder:
	def __init__(self, infoparser, tracelog):
		self.infoparser = infoparser
		self.tracelog = tracelog
		self.histories = []

	def build(self):
		debug = False
		lasts = {}
		stacks = {}
		d = 0

		callname = re.sub(r'\.log\.info$', '.log.call', self.infoparser.infoname)
		fp = open(callname, 'w')
		fp.write('[')

		while self.tracelog.max_d is None or d < self.tracelog.max_d:
			tdat = self.tracelog.get_data(d)
			if not tdat:
				break

			tid = tdat.data['thread']
			if tid not in stacks:
				stacks[tid] = LogStack(tid)
			if tid not in lasts:
				lasts[tid] = None

			if debug:
				print(tdat)

			for addr in tdat.unpack():
				block = self.infoparser.basic_blocks.get(addr)
				symbol = self.infoparser.symbols.get(addr)

				last_addr = lasts[tid]

				lasts[tid] = addr

				if not last_addr:
					if debug:
						print("Start: 0x%08x" % (addr,))
					continue

				last_block = self.infoparser.basic_blocks.get(last_addr)
				last_symbol = self.infoparser.symbols.get(last_addr)

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

				elif last_symbol and symbol:

					if debug:
						print("0x%08x %s -> @ 0x%08x %s" % (last_addr, last_symbol['name'], addr, symbol['name']))

					stacks[tid].append(last_symbol)

				else:
					print("-- @ 0x%08x -> @ 0x%08x" % (last_addr, addr))

			output = '{\n\t\"lasts": {'
			output += ', '.join(['"%x": "0x%08x"' % (tid, _last) for tid, _last in lasts.iteritems()])
			output += '},\n\t"stacks": {'
			output += ','.join(
				['\n\t\t"%x": [%s]' % (tid, ', '.join(['"0x%08x"' % x['entry'] for x in _stack.stack])) for tid, _stack in stacks.iteritems()]
			)
			output += '\n\t}\n},'
			fp.write(output)

			print(output)

			d += 1

		fp.write('{}]')
		fp.close()
