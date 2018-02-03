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

	def fill(self, addrs, infoparser):
		if addrs is None: return
		for last_addr in addrs:
			last_block = infoparser.basic_blocks.get(last_addr)
			last_symbol = infoparser.symbols.get(last_addr)
			if last_block:
				self.append(last_block)
			elif last_symbol:
				self.append(last_symbol)


class CallStackBuilder:
	def __init__(self, infoparser, tracelog):
		self.infoparser = infoparser
		self.tracelog = tracelog
		self.histories = []

	def parse(self):
		callname = re.sub(r'\.log\.info$', '.log.call', self.infoparser.infoname)
		if not os.path.exists(callname):
			return False

		fp = open(callname, 'r')
		json_rows = json.load(fp)
		fp.close()

		self.histories = []
		for row in json_rows:
			if not len(row): continue

			lasts = {}
			for tid_, addr in row['lasts'].iteritems():
				if '0x' not in tid_: tid_ = '0x' + tid_
				tid = int(tid_, 0)
				lasts[tid] = int(addr, 0)

			stacks = {}
			for tid_, addrs in row['stacks'].iteritems():
				if '0x' not in tid_: tid_ = '0x' + tid_
				tid = int(tid_, 0)
				stacks[tid] = [int(addr, 0) for addr in addrs]

			history = {
				'lasts': lasts,
				'stacks': stacks
			}

			self.histories.append(history)

	def draw(self, d):
		debug = False

		tdat = self.tracelog.get_data(d)
		if not tdat:	return False
		
		tid = tdat.data['thread']
		logstack = LogStack(tid)
		before = None

		if d > 0:
			history = self.histories[d-1]
			before = history['lasts'].get(tid)
			logstack.fill(history['stacks'].get(tid), self.infoparser)

		if debug:
			print(tdat)

		for addr in tdat.unpack():
			block = self.infoparser.basic_blocks.get(addr)
			symbol = self.infoparser.symbols.get(addr)

			last_addr = before
			before = addr

			if not last_addr:
				if debug:	print("Start: 0x%08x" % (addr,))
				continue

			last_block = self.infoparser.basic_blocks.get(last_addr)
			last_symbol = self.infoparser.symbols.get(last_addr)

			# block -> block
			if last_block and block:

				if debug:
					print("0x%08x %s -> 0x%08x" % (last_block['last_pc'], last_block['last_asm'], addr))

				if re.match(r'call', last_block['last_asm']):
					if addr != last_block['end']:
						logstack.append(last_block)

				elif re.match(r'ret', last_block['last_asm']):
					item = logstack.peek_block(addr)
					if item:
						logstack.pop_into(addr)

			# block -> symbol
			elif last_block and symbol:

				if debug:
					print("0x%08x %s -> 0x%08x %s" % (last_block['last_pc'], last_block['last_asm'], addr, symbol['name']))

				if re.match(r'call', last_block['last_asm']):
					logstack.append(last_block)

			# symbol -> block
			elif last_symbol and block:

				if debug:
					print("0x%08x %s -> 0x%08x" % (last_addr, last_symbol['name'], addr))

				item = logstack.peek_block(addr)
				if item:
					logstack.pop_into(addr)
				else:
					logstack.append(last_symbol)

			elif last_symbol and symbol:

				if debug:
					print("0x%08x %s -> @ 0x%08x %s" % (last_addr, last_symbol['name'], addr, symbol['name']))

				logstack.append(last_symbol)

			else:
				print("-- @ 0x%08x -> @ 0x%08x" % (last_addr, addr))

		print self.histories[d]

		if before != self.histories[d]['lasts'][tid]:
			print "Before is invalid!"
			print before
		if [x['entry'] for x in logstack.stack] != self.histories[d]['stacks'][tid]:
			print "Logstack is invalid!"
			print logstack.stack
			

	def build(self):
		debug = False
		lasts = {}
		stacks = {}
		d = 0

		callname = re.sub(r'\.log\.info$', '.log.call', self.infoparser.infoname)
		if os.path.exists(callname):
			return False

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
			output += ', '.join(['"0x%X": "0x%08x"' % (tid, _last) for tid, _last in lasts.iteritems()])
			output += '},\n\t"stacks": {'
			output += ','.join(
				['\n\t\t"0x%X": [%s]' % (tid, ', '.join(['"0x%08x"' % x['entry'] for x in _stack.stack])) for tid, _stack in stacks.iteritems()]
			)
			output += '\n\t}\n},'
			fp.write(output)

			print(output)

			d += 1

		fp.write('{}]')
		fp.close()

		return True
