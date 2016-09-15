# -*- coding: utf-8 -*-

import pefile
import os, sys
import struct

sys.path.append(os.getenv('PSX_PATH'))
import trace_info

def get_registry_value(key, subkey, value):
    import _winreg
    key = getattr(_winreg, key)
    handle = _winreg.OpenKey(key, subkey)
    (value, type) = _winreg.QueryValueEx(handle, value)
    return value

cputype = get_registry_value(
    "HKEY_LOCAL_MACHINE", 
    "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
    "ProcessorNameString")

cpuspeed = get_registry_value(
    "HKEY_LOCAL_MACHINE", 
    "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
    "~MHz")

class TraceData:
	def __init__(self, data, base_ts):
		self.data = data
		self.ts = (data['ts'] - base_ts)/(cpuspeed * 1000000.0)

	def __repr__(self):
		s = ''		

		if self.data['code'] == 0:
			s = 'trace'
		elif self.data['code'] == 1:
			s = 'thread-init'
		elif self.data['code'] == 2:
			s = 'thread-exit'

		s = "%.3f %s<%x>" % (self.ts, s, self.data['thread'])
		return s

	def is_trace(self):
		return self.data['code'] == 0

	def get_count(self):
		return self.data['count']

	def get_trace(self, i):
		d = struct.unpack('<I', self.data['data'][i*4: i*4+4])
		return d[0]

class TraceLog:
	def __init__(self, count=0):
		if count:
			fname = "trace.log.%d" % (count,)
		else:
			fname = "trace.log"
		fname = os.path.join(os.getenv('PSX_PATH'), fname);
		self.f = open(fname, 'rb')
		self.locs = []
		self.base_ts = None
		self.main_thread = None

	def __del__(self):
		self.f.close()

	def seek_pos(self, i):
		while len(self.locs) <= i:
			loc = self.f.tell()
			if not self._get_pkt(seek=True):
				return False

			self.locs.append( loc )			

		self.f.seek(self.locs[i])
		return True

	def get_data(self, i):
		if not self.seek_pos(i): return

		data = self._get_pkt(seek=False)
		return data

	def _get_pkt(self, seek):
		x = self.f.read(4 + 8 + 4)
		if x is None or len(x) == 0: return False

		hdr = struct.unpack('<IQI', x)
		data = {
			'code': hdr[0],
			'ts': hdr[1],
			'thread': hdr[2]
		}

		if hdr[0] == 1:
			if self.base_ts is None:
				self.base_ts = data['ts']
			if self.main_thread is None:
				self.main_thread = data['thread']

		if hdr[0] == 0:
			x = self.f.read(4)
			cnt = struct.unpack('<I', x)
			
			if seek:
				self.f.seek(cnt[0] * 4,1)
			else:
				data['count'] = cnt[0]
				data['data'] = buffer(self.f.read(cnt[0] * 4))

		if seek:
			return True
		
		return TraceData(data, self.base_ts)

class Main:
	def __init__(self):
		pass

	def run(self):
		self.tl = TraceLog(0)
		for i in xrange(0, 24):
			self.d = self.tl.get_data(i)
			if not self.d.is_trace(): continue

			print self.d

			for j in xrange(0, min(10, self.d.get_count())):
				entry = self.d.get_trace(j)
				b = trace_info.blocks.get(entry)
				if b:
					print b
					continue

				s = trace_info.symbols.get(entry)
				if s:
					print s
					continue

				print entry

			break	

if __name__ == '__main__':
	main = Main()
	main.run()