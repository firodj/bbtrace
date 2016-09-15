# -*- coding: utf-8 -*-

import pefile
import os, sys
import struct
import pefile
import tracelog
import capstone

sys.path.append(os.getenv('PSX_PATH'))
import trace_info

def find_pe_section(pe, rva):
	for section in pe.sections:
		if section.contains_rva(rva):
			return section

class Main:
	def __init__(self):
		pass

	def load_pe(self):
		fname = os.path.join(os.getenv('PSX_PATH'), 'psxfin.exe');
		pe = pefile.PE(fname)

		eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		print hex(pe.OPTIONAL_HEADER.ImageBase + eop)
		code_section = find_pe_section(pe, eop)
		
		print("[+] Code section found at offset: "
			"{:#x} [size: {:#x}]".format(code_section.PointerToRawData,
										code_section.SizeOfRawData))

		# get first 10 bytes at entry point and dump them
		code_at_oep = code_section.get_data(eop, 10)
		print("[*] Code at EOP:\n{}".
			format(" ".join("{:02x}".format(ord(c)) for c in code_at_oep)))

		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			print entry.dll
			for imp in entry.imports:
				print '\t', hex(imp.address), imp.name

		self.pe = pe

	def run(self):
		self.tlog = tracelog.TraceLog()
		
		self.d = self.tlog.get_data(0)
		print self.d

		for j in xrange(0, min(100, self.d.get_count())):
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

if __name__ == '__main__':
	main = Main()
	main.load_pe()