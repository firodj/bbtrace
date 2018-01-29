# -*- coding: utf-8 -*-

import os, sys
import struct
from collections import namedtuple
import re


if os.name == 'nt':
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
		self.ts = data['ts'] - base_ts  # )/(cpuspeed * 1000000.0)

	def __repr__(self):
		s = ''

		if self.data['code'] == 0:
			s = 'trace'
		
		s = "ts:%d tid:%08x code:%d (%s) size:%d" % (self.ts, self.data['thread'], self.data['code'], s, self.data['count'])
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
	def __init__(self, zeroname):
		self.locs = []
		self.base_ts = None
		
		self.fp = None
		self.max_d = None

		if not re.match(r'.*\.log\.0001$', zeroname):
			raise Exception("Need .log.0001 file")

		self.logname = re.sub(r'\.log\.\d+$', '.log.', zeroname)
		self.cache_data = None

	def get_loc(self, d):
		if self.max_d and d >= self.max_d:
			return None

		if d is not None and d < len(self.locs):
			return self.locs[d]
		elif len(self.locs):
			n, o = self.locs[-1]
			skip1st = True
		else:
			n, o = (1, 0)
			skip1st = False

		fname = "%s%04d" % (self.logname, n)
		if not os.path.exists(fname):
			raise Exception("Log file %s not exist" % (fname,))

		fp = open(fname, 'rb')
		fp.seek(o)

		while d is None or d >= len(self.locs):
			while True:
				o = fp.tell()
				data = self._get_pkt(fp, is_seeking=True)
				if not data:
					break

				if len(self.locs) == 0:
					self.base_ts = data['ts']

				if skip1st:
					skip1st = False
				else:
					self.locs.append( (n, o) )

			n += 1

			fp.close()
			fname = "%s%04d" % (self.logname, n)

			if not os.path.exists(fname):
				self.max_d = len(self.locs)
				break

			fp = open(fname, 'rb')
			fp.seek(0)

		if d is not None:
			if d < len(self.locs):
				return self.locs[d]
		elif len(self.locs):
			 return self.locs[-1]
		return None

	def get_data(self, d):
		loc = self.get_loc(d)
		if loc is None:
			return None

		if self.cache_data and self.cache_data[0] == d:
			return self.cache_data[1]

		n, o = loc
		fname = "%s%04d" % (self.logname, n)
		fp = open(fname, 'rb')
		fp.seek(o)
		data = self._get_pkt(fp, is_seeking=False)
		fp.close()

		self.cache_data = (d, data)

		return data

	def _get_pkt(self, fp, is_seeking):
		x = fp.read(4 + 8 + 4)
		if x is None or len(x) == 0: return False

		hdr = struct.unpack('<IQI', x)
		data = {
			'code': hdr[0],
			'ts': hdr[1],
			'thread': hdr[2]
		}

		x = fp.read(4)
		cnt = struct.unpack('<I', x)
		data['count'] = cnt[0]

		if is_seeking:
			fp.seek(cnt[0] * 4, 1)
			return data

		data['data'] = buffer(fp.read(cnt[0] * 4))

		return TraceData(data, self.base_ts)
