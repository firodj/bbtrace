# -*- coding: utf-8 -*-

import os, sys
import struct
from collections import namedtuple

Function = namedtuple('Function',  ['entry', 'end', 'name'])
functions = dict()
labels = dict()

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
		
		s = "%.3f %s<%x>" % (self.ts, s, self.data['thread'])
		return s

	def is_trace(self):
		return self.data['code'] == 0

	def get_count(self):
		return self.data['count']

	def unpack(self, start=0):
		length = self.get_count() - start
		if length <= 0: return
		
		for entry in struct.unpack_from('<%dI' % (length,), self.data['data'], start*4):
			yield entry

	def get_trace(self, i):
		d = struct.unpack('<I', self.data['data'][i*4: i*4+4])
		return d[0]

class TraceLog:
	def __init__(self):		
		self.locs = []
		self.base_ts = None
		
		self.f = None

		self.load(0)
		self.seek_pos(0)

		self.cache_data = None

	def load(self, n=0):
		if n:
			fname = "trace.log.%d" % (n,)
		else:
			fname = "trace.log"
		fname = os.path.join(os.getenv('PSX_PATH'), fname);
		self.f = open(fname, 'rb')

	def __del__(self):
		if self.f:
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
		if self.cache_data and self.cache_data[0] == i:
			return self.cache_data[1]

		if not self.seek_pos(i): return

		data = self._get_pkt(seek=False)
		self.cache_data = (i, data)

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

		if self.base_ts is None:
			self.base_ts = data['ts']			
	
		x = self.f.read(4)
		cnt = struct.unpack('<I', x)
		
		if seek:
			self.f.seek(cnt[0] * 4, 1)
		else:
			data['count'] = cnt[0]
			data['data'] = buffer(self.f.read(cnt[0] * 4))

		if seek:
			return True
		
		return TraceData(data, self.base_ts)