import sys
import os
import re
from InfoParser import InfoParser
from TraceLog import TraceLog
import json


class FlameGraph:
	def __init__(self, max_x):
		self.max_x = max_x
		self.reset()

	def reset(self):
		self.x = 0
		self.last_y = None
		self.last_j = False
		self.lines = {}

	def notify_draw(self, logstack, action, item):
		if self.x >= self.max_x or action == 'STOP':
			self.stop()
			return True

		y = len(logstack.stack)
		if y not in self.lines:
			self.lines[y] = []

		if action == 'START':
			self.last_j = False
			self.lines[y].append( {
				'addr': item['entry'],
				'x0': self.x,
				'x1': None
			} )
		if action == 'PUSH':
			self.last_j = False
			self.x += 1
			self.lines[y].append( {
				'addr': item['entry'],
				'x0': self.x,
				'x1': None
			} )
		elif action == 'POP':
			self.last_j = False
			for pop_y in xrange(self.last_y, y, -1):
				self.lines[pop_y][-1]['x1'] = self.x
		elif action == 'JUMP':
			if not self.last_j:
				self.x += 1
			self.last_j = True

		self.last_y = y

	def stop(self):
		for y, line in self.lines.iteritems():
			last_f = line[-1]
			if last_f['x1'] is None:
				last_f['x1'] = self.x

class LogStack:
	def __init__(self, thread, callback=None):
		self.thread = thread
		self.stack = []
		self.callback = callback

	def append(self, item):
		self.stack.append(item)

	def notify(self, action, item):
		if self.callback:
			return self.callback(self, action, item)

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

	def peek_block_end(self, addr):
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

	def draw(self, d, max_x):
		tdat = self.tracelog.get_data(d)
		if not tdat:	return False
		
		tid = tdat.data['thread']
		self.drawing = FlameGraph(max_x)
		logstack = LogStack(tid, self.drawing.notify_draw)
		before = None
	
		if d > 0:
			history = self.histories[d-1]
			before = history['lasts'].get(tid)
			logstack.fill(history['stacks'].get(tid), self.infoparser)

		before, logstack = self.build_stack(tdat, before, logstack)

		if False:
			print self.histories[d]
			if before != self.histories[d]['lasts'][tid]:
				print "Before is invalid!"
				print before
			if [x['entry'] for x in logstack.stack] != self.histories[d]['stacks'][tid]:
				print "Logstack is invalid!"
				print logstack.stack

		return self.drawing.lines

	def build_stack(self, tdat, before, logstack):
		debug = False

		if debug:	print(tdat)

		for addr in tdat.unpack():
			err = None
			block = self.infoparser.basic_blocks.get(addr)
			symbol = self.infoparser.symbols.get(addr)

			last_addr = before
			before = addr

			if not last_addr:
				err = logstack.notify('START', block)
				if err == True:	break
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
						err = logstack.notify('PUSH', block)

				elif re.match(r'ret', last_block['last_asm']):
					item = logstack.peek_block_end(addr)
					if item:
						logstack.pop_into(addr)
						err = logstack.notify('POP', block)

				elif re.match(r'j', last_block['last_asm']):
					err = logstack.notify('JUMP', block)

			# block -> symbol
			elif last_block and symbol:

				if debug:
					print("0x%08x %s -> 0x%08x %s" % (last_block['last_pc'], last_block['last_asm'], addr, symbol['name']))

				if re.match(r'call', last_block['last_asm']):
					logstack.append(last_block)
					err = logstack.notify('PUSH', symbol)

			# symbol -> block
			elif last_symbol and block:

				if debug:
					print("0x%08x %s -> 0x%08x" % (last_addr, last_symbol['name'], addr))

				item = logstack.peek_block_end(addr)
				if item:
					logstack.pop_into(addr)
					err = logstack.notify('POP', block)
				else:
					logstack.append(last_symbol)
					err = logstack.notify('PUSH', block)

			elif last_symbol and symbol:

				if debug:
					print("0x%08x %s -> @ 0x%08x %s" % (last_addr, last_symbol['name'], addr, symbol['name']))

				logstack.append(last_symbol)
				err = logstack.notify('PUSH', symbol)

			else:
				print("-- @ 0x%08x -> @ 0x%08x" % (last_addr, addr))

			if err == True:	break

		logstack.notify('STOP', None)
		return (before, logstack)
			

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
			if not tdat:	break

			tid = tdat.data['thread']
			if tid not in stacks:
				stacks[tid] = LogStack(tid)
			if tid not in lasts:
				lasts[tid] = None

			before, logstack = self.build_stack(tdat, lasts[tid], stacks[tid])
			lasts[tid] = before
			stacks[tid] = logstack

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
