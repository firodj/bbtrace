<?php

class PeParser
{
    private $headers;
    private $fp;
    private $name;
    private $optMagic;
    private $imageBase;
    private $numSecs;

    const NUM_DIR_ENTRIES = 16;
    const DIR_NAMES = ['EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 
        'SECURITY', 'BASERELOC', 'DEBUG', 'ARCHITECTURE',
        'GLOBALPTR', 'TLS', 'LOAD_CONFIG', 'BOUND_IMPORT',
        'IAT', 'DELAY_IMPORT', 'COM_DESCRIPTOR'];
    const NT_OPTIONAL_32_MAGIC = 0x10B;
    const NT_OPTIONAL_64_MAGIC = 0x20B;
    const NT_SHORT_NAME_LEN = 8;
    const sizeof_IMAGE_DOS_HEADER = 0x40;
    const sizeof_IMAGE_DATA_DIRECTORY = 0x8;
    const sizeof_IMAGE_SECTION_HEADER = 0x28;
    const sizeof_IMAGE_FILE_HEADER = 0x14;
    const sizeof_IMAGE_IMPORT_DESCRIPTOR = 0x14;
    const sizeof_IMAGE_RESOURCE_DIRECTORY = 0x10;
    const sizeof_IMAGE_EXPORT_DIRECTORY = 0x28;

    public function __construct($name)
    {
        $this->name = $name;
        $this->headers = [];
        $this->fp = null;
        $this->optMagic = null;
        $this->imageBase = null;
        $this->numSecs = 0;
    }

    protected function getHeaderValue($name)
    {
        $header = $this->headers[$name];

        if ($header[2] == 'h*') return '<BINARY>';

        fseek($this->fp, $header[0], SEEK_SET);
        $data = fread($this->fp, $header[1]);
        if ($header[2] == 'x*') return iconv('UTF-16LE', 'UTF-8', $data);
        $s = unpack($header[2], $data);
        return $s[1];
    }

    public function is32() {
        return $this->optMagic == self::NT_OPTIONAL_32_MAGIC;
    }

    public function is64() {
        return $this->optMagic == self::NT_OPTIONAL_64_MAGIC;
    }

    public function open()
    {
        if (!isset($this->fp)) {
            $this->fp = $fp = fopen($this->name, 'rb');
        }
    }

    public function close()
    {
        if ($this->fp) {
            fclose($this->fp);
            unset($this->fp);
        }
    }

    public function parsePe()
    {
        $this->open();

        $this->headers['dos.e_magic']    = [0, 2, 'a2'];
        $this->headers['dos.e_cblp']     = [2, 2, 'v'];
        $this->headers['dos.e_cp']       = [4, 2, 'v'];
        $this->headers['dos.e_crlc']     = [6, 2, 'v'];
        $this->headers['dos.e_cparhdr']  = [8, 2, 'v'];
        $this->headers['dos.e_minalloc'] = [0xa, 2, 'v'];
        $this->headers['dos.e_maxalloc'] = [0xc, 2, 'v'];
        $this->headers['dos.e_ss']       = [0xe, 2, 'v'];
        $this->headers['dos.e_sp']       = [0x10, 2, 'v'];
        $this->headers['dos.e_sum']      = [0x12, 2, 'v'];
        $this->headers['dos.e_ip']       = [0x14, 2, 'v'];
        $this->headers['dos.e_cs']       = [0x16, 2, 'v'];
        $this->headers['dos.e_lfarlc']   = [0x18, 2, 'v'];
        $this->headers['dos.e_ovno']     = [0x1a, 2, 'v'];
        $this->headers['dos.e_res']      = [0x1c, 8, 'v*'];
        $this->headers['dos.e_oemid']    = [0x24, 2, 'v'];
        $this->headers['dos.e_oeminfo']  = [0x26, 2, 'v'];
        $this->headers['dos.e_res2']     = [0x28, 20, 'v*'];
        $this->headers['dos.e_lfanew']   = [0x3c, 4, 'V'];

        $pe_ofs = $this->getHeaderValue('dos.e_lfanew');

        $this->headers['nt.Signature']            = [$pe_ofs, 4, 'a2'];
        $this->headers['file.Machine']              = [$pe_ofs +4, 2, 'v'];
        $this->headers['file.NumberOfSections']     = [$pe_ofs +6, 2, 'v'];
        $this->headers['file.TimeDateStamp']        = [$pe_ofs +8, 4, 'V'];
        $this->headers['file.PointerToSymbolTable'] = [$pe_ofs +0x0b, 4, 'V'];
        $this->headers['file.NumberOfSymbols']      = [$pe_ofs +0x10, 4, 'V'];
        $this->headers['file.SizeOfOptionalHeader'] = [$pe_ofs +0x14, 2, 'v'];
        $this->headers['file.Characteristics']      = [$pe_ofs +0x16, 2, 'v'];

        $opt_ofs = $pe_ofs + 4 + self::sizeof_IMAGE_FILE_HEADER;

        $opt_sz = $this->getHeaderValue('file.SizeOfOptionalHeader');

        $this->headers['opt.Magic']                 = [$opt_ofs, 2, 'v'];
        $this->optMagic = $this->getHeaderValue('opt.Magic');

        $this->headers['opt.MajorLinkerVersion']    = [$opt_ofs +2, 1, 'C'];
        $this->headers['opt.MinorLinkerVersion']    = [$opt_ofs +3, 1, 'C'];
        $this->headers['opt.SizeOfCode']            = [$opt_ofs +4, 4, 'V'];
        $this->headers['opt.SizeOfInitializedData'] = [$opt_ofs +8, 4, 'V'];
        $this->headers['opt.SizeOfUninitializedData'] = [$opt_ofs +0xc, 4, 'V'];
        $this->headers['opt.AddressOfEntryPoint']   = [$opt_ofs + 0x10, 4, 'V'];
        $this->headers['opt.BaseOfCode']            = [$opt_ofs + 0x14, 4, 'V'];
        $this->headers['opt.BaseOfData']            = [$opt_ofs + 0x18, 4, 'V'];
        $this->headers['opt.ImageBase']             = [$opt_ofs + 0x1c, 4, 'V'];
        $this->imageBase = $this->getHeaderValue('opt.ImageBase');

        $this->headers['opt.SectionAlignment']      = [$opt_ofs + 0x20, 4, 'V'];
        $this->headers['opt.FileAlignment']         = [$opt_ofs + 0x24, 4, 'V'];
        $this->headers['opt.MajorOperatingSystemVersion'] = [$opt_ofs + 0x28, 2, 'v'];
        $this->headers['opt.MinorOperatingSystemVersion'] = [$opt_ofs + 0x2a, 2, 'v'];
        $this->headers['opt.MajorImageVersion']     = [$opt_ofs + 0x2c, 2, 'v'];
        $this->headers['opt.MinorImageVersion']     = [$opt_ofs + 0x2e, 2, 'v'];
        $this->headers['opt.MajorSubsystemVersion'] = [$opt_ofs + 0x30, 2, 'v'];
        $this->headers['opt.MinorSubsystemVersion'] = [$opt_ofs + 0x32, 2, 'v'];
        $this->headers['opt.Win32VersionValue']     = [$opt_ofs + 0x34, 4, 'V'];
        $this->headers['opt.SizeOfImage']           = [$opt_ofs + 0x38, 4, 'V'];
        $this->headers['opt.SizeOfHeaders']         = [$opt_ofs + 0x3c, 4, 'V'];
        $this->headers['opt.Checksum']              = [$opt_ofs + 0x40, 4, 'V'];
        $this->headers['opt.Subsystem']             = [$opt_ofs + 0x44, 2, 'v'];
        $this->headers['opt.DllCharacteristics']    = [$opt_ofs + 0x46, 2, 'v'];
        $this->headers['opt.SizeOfStackReserve']    = [$opt_ofs + 0x48, 4, 'V'];
        $this->headers['opt.SizeOfStackCommit']     = [$opt_ofs + 0x4c, 4, 'V'];
        $this->headers['opt.SizeOfHeapReserve']     = [$opt_ofs + 0x50, 4, 'V'];
        $this->headers['opt.SizeOfHeapCommit']      = [$opt_ofs + 0x54, 4, 'V'];
        $this->headers['opt.LoaderFlags']           = [$opt_ofs + 0x58, 4, 'V'];
        $this->headers['opt.NumberOfRvaAndSizes']   = [$opt_ofs + 0x5c, 4, 'V'];

        $data_dir = $opt_ofs + 0x60;

        for ($n = 0; $n < self::NUM_DIR_ENTRIES; $n++) {
            $name = self::DIR_NAMES[$n] ?? $n;
            $this->headers[sprintf('opt.DataDirectory@%s.VirtualAddress', $name)] =
                [$data_dir + ($n * self::sizeof_IMAGE_DATA_DIRECTORY), 4, 'V'];
            $this->headers[sprintf('opt.DataDirectory@%s.Size', $name)] =
                [$data_dir + ($n * self::sizeof_IMAGE_DATA_DIRECTORY)+4, 4, 'V'];
        }

        $secs_ofs = $opt_ofs + $opt_sz;

        $this->numSecs = $this->getHeaderValue('file.NumberOfSections');
        for ($n = 0; $n < $this->numSecs; $n++) {
            $this->headers[sprintf('secs@%d.Name', $n)]  = [$secs_ofs + ($n * self::sizeof_IMAGE_SECTION_HEADER), self::NT_SHORT_NAME_LEN, 'a*'];

            $misc = $secs_ofs + ($n * self::sizeof_IMAGE_SECTION_HEADER) + self::NT_SHORT_NAME_LEN;
            $this->headers[sprintf('secs@%d.VirtualSize', $n)]     = [$misc, 4, 'V'];
            $this->headers[sprintf('secs@%d.VirtualAddress', $n)]  = [$misc + 4, 4, 'V']; // RVA
            $this->headers[sprintf('secs@%d.SizeOfRawData', $n)]   = [$misc + 8, 4, 'V'];
            $this->headers[sprintf('secs@%d.PointerToRawData', $n)]  = [$misc + 0xc, 4, 'V'];
            $this->headers[sprintf('secs@%d.PointerToRelocations', $n)] = [$misc + 0x10, 4, 'V'];
            $this->headers[sprintf('secs@%d.PointerToLinenumbers', $n)] = [$misc + 0x14, 4, 'V'];
            $this->headers[sprintf('secs@%d.NumberOfRelocations', $n)] = [$misc + 0x18, 2, 'v'];
            $this->headers[sprintf('secs@%d.NumberOfLinenumbers', $n)] = [$misc + 0x1a, 2, 'v'];
            $this->headers[sprintf('secs@%d.Characteristics', $n)] = [$misc + 0x1c, 4, 'V'];

            $s_sz = $this->getHeaderValue(sprintf('secs@%d.VirtualSize', $n));
            $s_raw = $this->getHeaderValue(sprintf('secs@%d.PointerToRawData', $n));
            $this->headers[sprintf('secs@%d.Data', $n)]  = [$s_raw, $s_sz, 'h*'];
        }

        $this->parseImports();
        $this->parseExports();
        $this->parseResources();
    }

    public function dump()
    {
        $this->open();

        foreach($this->headers as $name=>$header) {
            $value = $this->getHeaderValue($name);
            printf("0x%04x %s %s\n", $header[0], $name, is_string($value) ? $value : '0x'.dechex($value));
        }
    }

    public function findSection($rva)
    {
        for ($n = 0; $n < $this->numSecs; $n++) {
            $s_sz = $this->getHeaderValue(sprintf('secs@%d.VirtualSize', $n));
            $s_rva = $this->getHeaderValue(sprintf('secs@%d.VirtualAddress', $n));

            $low = $s_rva;
            $high = $low + $s_sz;

            if ($rva >= $low && $rva < $high) {
                $raw = $this->getHeaderValue(sprintf('secs@%d.PointerToRawData', $n));
                return (object)['n' => $n, 'ofs' => $rva - $s_rva, 'sz' => $s_sz, 'raw' => $raw];
            }
        }
    }

    public function findString($rva)
    {
        $s = $this->findSection($rva);
        if ($s) {
            $raw = $s->raw + $s->ofs;

            fseek($this->fp, $raw, SEEK_SET);
            $data = fread($this->fp, min($s->sz - $s->ofs, 256));

            $len = strpos($data, 0);

            return (object)['raw' => $raw, 'len' => $len];
        }
        return null;
    }

    public function parseImports()
    {
        $va = $this->getHeaderValue('opt.DataDirectory@IMPORT.VirtualAddress');
        $sz = $this->getHeaderValue('opt.DataDirectory@IMPORT.Size');

        $s = $this->findSection($va);
        if (is_null($s)) return;

        $imp_ofs = $s->raw + $s->ofs;

        for($n = 0;;$n++, $imp_ofs += self::sizeof_IMAGE_IMPORT_DESCRIPTOR) {
            $this->headers[sprintf('import@%d.LookupTableRVA', $n)] = [$imp_ofs, 4, 'V'];
            $this->headers[sprintf('import@%d.TimeDateStamp', $n)]      = [$imp_ofs +4, 4, 'V'];
            $this->headers[sprintf('import@%d.ForwarderChain', $n)] = [$imp_ofs +8, 4, 'V'];
            $this->headers[sprintf('import@%d.NameRVA', $n)]        = [$imp_ofs +0xc, 4, 'V'];
            $this->headers[sprintf('import@%d.AddressRVA', $n)]     = [$imp_ofs +0x10, 4, 'V'];

            $lookup_rva = $this->getHeaderValue(sprintf('import@%d.LookupTableRVA', $n));
            if (!$lookup_rva) break;

            $name_rva = $this->getHeaderValue(sprintf('import@%d.NameRVA', $n));

            $st = $this->findString($name_rva);
            if ($st) {
                $this->headers[sprintf('import@%d.Name', $n)] = [$st->raw, $st->len, 'a*'];
            }

            $s = $this->findSection($lookup_rva);
            if (is_null($s)) continue;

            $sym_ofs = $s->raw + $s->ofs;

            $iat_rva = $this->getHeaderValue(sprintf('import@%d.AddressRVA', $n));
            $s = $this->findSection($iat_rva);
            if (is_null($s)) continue;

            $iat_ofs = $s->raw + $s->ofs;

            for ($y = 0;;$y++, $sym_ofs += 4, $iat_ofs += 4) {
                $k = sprintf('import@%d.sym@%d.NameRVA', $n, $y);
                $this->headers[$k] = [$sym_ofs, 4, 'V'];

                $val32 = $this->getHeaderValue($k);

                $k = sprintf('import@%d.sym@%d.AddressVA', $n, $y);
                $this->headers[$k] = [$iat_ofs, 4, 'V'];

                if (!$val32) break;

                $ord = $val32 >> 31;
                if ($ord == 0) {
                    $st = $this->findString($val32 + 2);
                    if ($st) {
                        $k = sprintf('import@%d.sym@%d.Hint', $n, $y);
                        $this->headers[$k] = [$st->raw - 2, 2, 'v'];
                        $k = sprintf('import@%d.sym@%d.Name', $n, $y);
                        $this->headers[$k] = [$st->raw, $st->len, 'a*'];
                    }
                } else {
                    $k = sprintf('import@%d.sym@%d.Ordinal', $n, $y);
                    $this->headers[$k] = [$sym_ofs, 2, 'v'];
                }
            }
        }
    }

    public function parseExports()
    {
        $va = $this->getHeaderValue('opt.DataDirectory@EXPORT.VirtualAddress');
        $sz = $this->getHeaderValue('opt.DataDirectory@EXPORT.Size');

        $s = $this->findSection($va);
        if (is_null($s)) return;

        $exp_ofs = $s->raw + $s->ofs;

        $this->headers['export.Characteristics']   = [$exp_ofs, 4, 'V'];
        $this->headers['export.TimeDateStamp'] = [$exp_ofs + 4, 4, 'V'];
        $this->headers['export.MajorVersion']  = [$exp_ofs + 8, 2, 'v'];
        $this->headers['export.MinorVersion']  = [$exp_ofs + 0xa, 2, 'v'];
        $this->headers['export.NameRVA']       = [$exp_ofs + 0xc, 4, 'V'];
        $this->headers['export.OrdinalBase']           = [$exp_ofs + 0x10, 4, 'V'];
        $this->headers['export.NumberOfFunctions']     = [$exp_ofs + 0x14, 4, 'V'];
        $this->headers['export.NumberOfNames']         = [$exp_ofs + 0x18, 4, 'V'];
        $this->headers['export.AddressOfFunctions']    = [$exp_ofs + 0x1c, 4, 'V'];
        $this->headers['export.AddressOfNames']         = [$exp_ofs + 0x20, 4, 'V'];
        $this->headers['export.AddressOfNameOrdinals'] = [$exp_ofs + 0x24, 4, 'V'];

        $rva = $this->getHeaderValue('export.NameRVA');
        $st = $this->findString($rva);
        if ($st) {
            $this->headers['export.Name'] = [$st->raw, $st->len, 'a*'];
        }
        $names_num = $this->getHeaderValue('export.NumberOfNames');

        $eats_rva   = $this->getHeaderValue('export.AddressOfFunctions');
        $names_rva = $this->getHeaderValue('export.AddressOfNames');
        $ords_rva   = $this->getHeaderValue('export.AddressOfNameOrdinals');

        for($n = 0; $n < $names_num; $n++, $names_rva += 4, $ords_rva += 2) {
            $s = $this->findSection($names_rva);
            if ($s) {
                $this->headers[sprintf('export.sym@%d.NameRVA', $n)] = [$s->raw + $s->ofs, 4, 'V'];

                $name_rva = $this->getHeaderValue(sprintf('export.sym@%d.NameRVA', $n));

                $st = $this->findString($name_rva);
                if($st) {
                    $this->headers[sprintf('export.sym@%d.Name', $n)] = [$st->raw, $st->len, 'a*'];
                }
            }

            $s = $this->findSection($ords_rva);
            if ($s) {
                $this->headers[sprintf('export.sym@%d.NameOrdinal', $n)] = [$s->raw + $s->ofs, 2, 'v'];

                $ord = $this->getHeaderValue(sprintf('export.sym@%d.NameOrdinal', $n));

                $s = $this->findSection($eats_rva + ($ord * 4));
                if ($s) {
                    $this->headers[sprintf('export.sym@%d.SymbolRVA', $n)] = [$s->raw + $s->ofs, 4, 'V'];
                }
            }
        }
    }

    public function parseResources()
    {
        $va = $this->getHeaderValue('opt.DataDirectory@RESOURCE.VirtualAddress');
        $sz = $this->getHeaderValue('opt.DataDirectory@RESOURCE.Size');

        $s = $this->findSection($va);
        if (is_null($s)) return;

        $raw = $s->raw + $s->ofs;

        $dirs=[ [0, [] ] ];
        while($d = array_shift($dirs)) {
            $ofs = $d[0];
            $parents = $d[1];

            $p = '';
            if (count($parents)) {
                $p = implode('', array_map(function($x) { return sprintf('.entry@%d', $x); }, $parents));
            }

            $res_ofs = $raw + $ofs;
            $this->headers[sprintf('resource%s.Characteristics', $p)] = [$res_ofs, 4, 'V'];
            $this->headers[sprintf('resource%s.TimeDateStamp', $p)]   = [$res_ofs +4, 4, 'V'];
            $this->headers[sprintf('resource%s.MajorVersion', $p)] = [$res_ofs +8, 2, 'v'];
            $this->headers[sprintf('resource%s.MinorVersion', $p)] = [$res_ofs +0xa, 2, 'v'];
            $this->headers[sprintf('resource%s.NumberOfNamedEntries', $p)] = [$res_ofs +0xc, 2, 'v'];
            $this->headers[sprintf('resource%s.NumberOfIdEntries', $p)] = [$res_ofs +0xe, 2, 'v'];

            $name_ens = $this->getHeaderValue(sprintf('resource%s.NumberOfNamedEntries', $p));
            $id_ens = $this->getHeaderValue(sprintf('resource%s.NumberOfIdEntries', $p));

            if ($name_ens === 0 && $id_ens == 0) return true;

            $res_ofs += self::sizeof_IMAGE_RESOURCE_DIRECTORY;

            for ($y = 0; $y < ($name_ens + $id_ens); $y++, $res_ofs += 8) {
                $this->headers[sprintf('resource%s.entry@%d.ID', $p, $y)]   = [$res_ofs, 4, 'V'];
                $this->headers[sprintf('resource%s.entry@%d.Offset', $p, $y)] = [$res_ofs+4, 4, 'V'];

                $st_ofs = $this->getHeaderValue(sprintf('resource%s.entry@%d.ID', $p, $y));
                $is_st = $st_ofs >> 31;

                if ($is_st) {
                    // assert if ($y < $name_ens) {
                    $name_ofs = $raw + ($st_ofs & 0x0fffffff);

                    $this->headers[sprintf('resource%s.entry@%d.NameLength', $p, $y)]   = [$name_ofs, 2, 'v'];
                    $name_len = $this->getHeaderValue(sprintf('resource%s.entry@%d.NameLength', $p, $y));

                    $this->headers[sprintf('resource%s.entry@%d.Name', $p, $y)]   = [$name_ofs+2, $name_len*2, 'x*']; // UTF-16LE
                }

                $entry_ofs = $this->getHeaderValue(sprintf('resource%s.entry@%d.Offset', $p, $y));

                $is_dir = $entry_ofs >> 31;
                if ($is_dir) {
                    $dirs[] = [ $entry_ofs & 0x0ffffff, array_merge($parents, [$y]) ];
                } else {
                    $data_ofs = $raw + $entry_ofs;
                    $this->headers[sprintf('resource%s.entry@%d.OffsetToData', $p, $y)]   = [$data_ofs, 4, 'V']; // RVA
                    $this->headers[sprintf('resource%s.entry@%d.Size', $p, $y)] = [$data_ofs+4, 4, 'V'];
                    $this->headers[sprintf('resource%s.entry@%d.CodePage', $p, $y)] = [$data_ofs+8, 4, 'V'];
                    $this->headers[sprintf('resource%s.entry@%d.Reserved', $p, $y)] = [$data_ofs+0xc, 4, 'V'];

                    $dat_sz = $this->getHeaderValue(sprintf('resource%s.entry@%d.Size', $p, $y));
                    $dat_rva = $this->getHeaderValue(sprintf('resource%s.entry@%d.OffsetToData', $p, $y));

                    $s = $this->findSection($dat_rva);
                    if (is_null($s)) continue;

                    $this->headers[sprintf('resource%s.entry@%d.Data', $p, $y)] = [$s->raw + $s->ofs, $dat_sz, 'h*'];
                }
            }
        }
    }

    public static function main($argv)
    {
        if (count($argv) <= 1) {
            echo "Syntax: $argv[0] <file.exe>\n";
            return false;
        }

        $fname = $argv[1];
        if (preg_match('/^(.+\.(exe|dll))$/', $fname, $matches)) {
            $fname = $matches[1];
        } else {
            echo "Error: file name not match <file.exe>\n";
            return false;
        }

        $pe_parser = new PeParser($fname);

        $pe_parser->parsePe();
        $pe_parser->dump();

        return $pe_parser;
    }
}

if (basename(__FILE__) == basename($_SERVER["SCRIPT_FILENAME"])) {
    $pe_parser = PeParser::main($argv);
}
