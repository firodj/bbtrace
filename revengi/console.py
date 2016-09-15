# -*- coding: utf-8 -*-

import pefile
import os, sys
import struct
import pefile
import tracelog
import capstone

sys.path.append(os.getenv('PSX_PATH'))
import trace_info
import trace_label

def find_pe_section(pe, rva):
	for section in pe.sections:
		if section.contains_rva(rva):
			return section

def print_pe_imports(pe):
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		print entry.dll
		for imp in entry.imports:
			print '\t', hex(imp.address), imp.name

class Main:
	def __init__(self):
		pass

	def out_main(self):
		fname = os.path.join(os.getenv('PSX_PATH'), 'psxfin.exe');
		pe    = pefile.PE(fname)

		va_ep = 0x48b940
		b    = trace_info.blocks.get(va_ep)
		mod  = trace_info.modules.get(b.module)
		ep   = va_ep - mod.start
		end  = tracelog.functions[va_ep].end

		code_section = find_pe_section(pe, ep)
		
		print("[+] Code section found at offset: "
			"{:#x} [size: {:#x}]".format(code_section.PointerToRawData,
										code_section.SizeOfRawData))

		#code_at_ep = pe.get_memory_mapped_image()[ep:end]
		code_at_ep = code_section.get_data(ep, end-ep)
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
		md.detail = True
		f = open('winmain.asm', 'w')
		for i in md.disasm(code_at_ep, pe.OPTIONAL_HEADER.ImageBase+ ep):
			f.write("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))
		f.close()

	def all_block(self):
		tlog = tracelog.TraceLog()
		
		i = 0
		b_lo, b_hi = None, None

		while True:
			d = tlog.get_data(i)
			if not d: break

			for entry in d.unpack():				
				b = trace_info.blocks.get(entry)
				if not b: continue
				if b_lo is None or b_lo > entry: b_lo = entry
				if b_hi is None or b_hi < b.end: b_hi = b.end

			print i, hex(b_lo), hex(b_hi), b_hi-b_lo
			i += 1

	def load_pe(self):
		fname = os.path.join(os.getenv('PSX_PATH'), 'psxfin.exe');
		pe    = pefile.PE(fname)

		for section in pe.sections:
  			print (section.Name, hex(section.VirtualAddress),
    			hex(section.Misc_VirtualSize), section.SizeOfRawData )

		tlog = tracelog.TraceLog()
		d    = tlog.get_data(0)
		va_ep = d.get_trace(2)
		b    = trace_info.blocks.get(va_ep)
		mod  = trace_info.modules.get(b.module)
		ep   = va_ep - mod.start

		#eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		#print hex(pe.OPTIONAL_HEADER.ImageBase + eop)
		code_section = find_pe_section(pe, ep)
		
		print("[+] Code section found at offset: "
			"{:#x} [size: {:#x}]".format(code_section.PointerToRawData,
										code_section.SizeOfRawData))

		# get first 10 bytes at entry point and dump them
		code_at_ep = code_section.get_data(ep, 20)
		print("[*] Code at ep:\n{}".
			format(" ".join("{:02x}".format(ord(c)) for c in code_at_ep)))

		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
		md.detail = True
		for i in md.disasm(code_at_ep, pe.OPTIONAL_HEADER.ImageBase+ ep):
			print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

		addr = 0x522144 - pe.OPTIONAL_HEADER.ImageBase
		v = pe.get_memory_mapped_image()[addr:addr+16]
		print "0x522144 =", [hex(i) for i in struct.unpack('<IIII', v)];
		
		#addr = 0x14246a - pe.OPTIONAL_HEADER.ImageBase
		#data_section = find_pe_section(pe, addr)
		#v = data_section.get_data(addr, 4)
		#v = pe.get_memory_mapped_image()[addr:addr+40]
		#print repr(v), hex(struct.unpack('<I', v)[0])

		#for i in md.disasm(v, pe.OPTIONAL_HEADER.ImageBase+ addr):
		#	print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

		self.pe = pe

	def run(self):
		self.tlog = tracelog.TraceLog()
		
		self.d = self.tlog.get_data(0)
		print self.d

		for j in xrange(0, min(100, self.d.get_count())):
			entry = self.d.get_trace(j)
			b = trace_info.blocks.get(entry)
			if b:
				f = trace_label.functions.get(entry)
				if f:
					print b,f
				else:
					print b
				continue

			s = trace_info.symbols.get(entry)
			if s:
				print s
				continue

			print entry

	def parse(self):
		pass

if __name__ == '__main__':
	main = Main()
	main.run()