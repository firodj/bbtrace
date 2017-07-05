<?php

class PeParser
{
    private $headers;
    private $fp;
    private $name;
    private $optMagic;
    private $imageBase;

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

    public function __construct($name)
    {
        $this->name = $name;
        $this->headers = [];
        $this->fp = null;
        $this->optMagic = null;
        $this->imageBase = null;
    }

    protected function getHeaderValue($name)
    {
        $header = $this->headers[$name];

        fseek($this->fp, $header[0], SEEK_SET);
        $data = fread($this->fp, $header[1]);
        $s = unpack($header[2], $data);
        return $s[1];
    }

    public function is32() {
        return $this->optMagic == self::NT_OPTIONAL_32_MAGIC;
    }

    public function is64() {
        return $this->optMagic == self::NT_OPTIONAL_64_MAGIC;
    }

    public function parsePe()
    {
        $this->fp = $fp = fopen($this->name, 'rb');

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
            $this->headers[sprintf('secs@%d.VirtualAddress', $n)]  = [$misc + 4, 4, 'V'];
            $this->headers[sprintf('secs@%d.SizeOfRawData', $n)]   = [$misc + 8, 4, 'V'];
            $this->headers[sprintf('secs@%d.PointerToRawData', $n)]  = [$misc + 0xc, 4, 'V'];
            $this->headers[sprintf('secs@%d.PointerToRelocations', $n)] = [$misc + 0x10, 4, 'V'];
            $this->headers[sprintf('secs@%d.PointerToLinenumbers', $n)] = [$misc + 0x14, 4, 'V'];
            $this->headers[sprintf('secs@%d.NumberOfRelocations', $n)] = [$misc + 0x18, 2, 'v'];
            $this->headers[sprintf('secs@%d.NumberOfLinenumbers', $n)] = [$misc + 0x1a, 2, 'v'];
            $this->headers[sprintf('secs@%d.Characteristics', $n)] = [$misc + 0x1c, 4, 'V'];
        }

        $this->parseImports();

        // DUMP

        foreach($this->headers as $name=>$header) {
            $value = $this->getHeaderValue($name);
            printf("0x%04x %s %s\n", $header[0], $name, is_string($value) ? $value : '0x'.dechex($value));
        }

        fclose($fp);
    }

    public function parseImports()
    {
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
        return $pe_parser;
    }
}

$pe_parser = PeParser::main($argv);
